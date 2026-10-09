package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	utls "github.com/refraction-networking/utls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// ------------------------- AnyTLS 协议桥（进程内） -------------------------
//
// Xray-core 没有 AnyTLS 出站（上游明确不做），所以 AnyTLS 节点不能像其它节点那样
// 直接生成 Xray 出站。这里在本进程里起一个只监听 127.0.0.1 的 SOCKS5 小服务，
// 背后用 sing-anytls 客户端连 AnyTLS 服务器；Xray 侧把它当成 socks 出站：
//
//	应用 → Xray(入站 + 路由分流 + 统计) → 本机 AnyTLS 桥 → AnyTLS 服务器
//
// 与旧版（内嵌 sing-box.exe）相比：不再带 45 MB 的外部进程，没有子进程管理与
// 版本残留问题；Xray 仍是唯一的分流 / 统计 / 系统代理 / TUN 出口。
//
// TCP：SOCKS CONNECT → 一条 AnyTLS 流（目标地址原样交给服务器解析）。
// UDP：SOCKS UDP ASSOCIATE → UDP-over-TCP v2（sing-box 服务端默认支持）。
//
// 服务器地址在 Go 侧先解析成 IP（与 TUN 的 /32 防回环路由同一份缓存），
// 域名只用作 TLS SNI；TUN 模式下系统 DNS 已被劫持，交给系统解析会绕回隧道。

// anyTLSBridge 是一个运行中的 AnyTLS 桥。
type anyTLSBridge struct {
	addr   string // 127.0.0.1:port，供 Xray socks 出站连接
	ln     net.Listener
	client *anytls.Client
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.Mutex
	conns map[io.Closer]struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

// needsAnyTLSBridge 该协议是否必须走 AnyTLS 协议桥（Xray 内核无法直连）。
func needsAnyTLSBridge(protocol string) bool {
	return protocol == "AnyTLS"
}

// anyTLSDialTimeout 连服务器（TCP + TLS 握手）的上限。
const anyTLSDialTimeout = 10 * time.Second

// resolveNodeServerIP 预解析节点服务器地址（TUN 模式下防 DNS 回环）。
func resolveNodeServerIP(node NodeItem) string {
	ips := lookupNodeIPv4sCached(node.Address)
	if len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

// anyTLSHelloID 把分享链接里的 fp 映射成 uTLS 指纹；AnyTLS 常架在 CDN 后，默认用 Chrome。
func anyTLSHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random", "randomized":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// anyTLSServerName TLS SNI：显式 sni 优先，否则用域名形式的服务器地址；IP 地址不发 SNI。
func anyTLSServerName(node NodeItem) string {
	sni := firstNonEmpty(node.SNI, node.Address)
	if net.ParseIP(sni) != nil {
		return ""
	}
	return sni
}

// startAnyTLSBridge 为 node 起一个本地 AnyTLS 桥。
func startAnyTLSBridge(node NodeItem) (*anyTLSBridge, error) {
	if node.UUID == "" {
		return nil, fmt.Errorf("AnyTLS node missing password")
	}
	if node.Port <= 0 || node.Port > 65535 {
		return nil, fmt.Errorf("AnyTLS node has invalid port: %d", node.Port)
	}
	serverIP := resolveNodeServerIP(node)
	if serverIP == "" {
		serverIP = node.Address
	}
	server := net.JoinHostPort(serverIP, strconv.Itoa(node.Port))
	tlsCfg := &utls.Config{
		ServerName:         anyTLSServerName(node),
		InsecureSkipVerify: node.Insecure || anyTLSServerName(node) == "",
		MinVersion:         utls.VersionTLS12,
	}
	helloID := anyTLSHelloID(node.FP)

	dialOut := func(ctx context.Context) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, anyTLSDialTimeout)
		defer cancel()
		var d net.Dialer
		raw, err := d.DialContext(ctx, "tcp", server)
		if err != nil {
			return nil, err
		}
		tc := utls.UClient(raw, tlsCfg.Clone(), helloID)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("AnyTLS TLS handshake: %w", err)
		}
		return tc, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password:                 node.UUID,
		IdleSessionCheckInterval: 30 * time.Second,
		IdleSessionTimeout:       30 * time.Second,
		DialOut:                  dialOut,
		Logger:                   logger.NOP(), // 服务端推送 padding / alert 时会写日志，nil 会崩
	})
	if err != nil {
		cancel()
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		client.Close()
		cancel()
		return nil, err
	}
	b := &anyTLSBridge{
		addr:   ln.Addr().String(),
		ln:     ln,
		client: client,
		ctx:    ctx,
		cancel: cancel,
		conns:  map[io.Closer]struct{}{},
	}
	b.wg.Add(1)
	go b.serve()
	return b, nil
}

// Stop 关闭桥：停止监听，断开全部连接与 AnyTLS 会话。可重复调用。
func (b *anyTLSBridge) Stop() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		b.cancel()
		b.ln.Close()
		b.mu.Lock()
		for c := range b.conns {
			c.Close()
		}
		b.conns = map[io.Closer]struct{}{}
		b.mu.Unlock()
		b.client.Close()
	})
}

func (b *anyTLSBridge) track(c io.Closer) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		c.Close()
		return false
	}
	b.conns[c] = struct{}{}
	return true
}

func (b *anyTLSBridge) untrack(c io.Closer) {
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
	c.Close()
}

func (b *anyTLSBridge) serve() {
	defer b.wg.Done()
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		if !b.track(c) {
			continue
		}
		go func() {
			defer b.untrack(c)
			b.handleSocks(c)
		}()
	}
}

// ------------------------- 最小 SOCKS5 服务端（仅本机 Xray 使用） -------------------------

const (
	socksVer         = 5
	socksCmdConnect  = 1
	socksCmdUDPAssoc = 3
)

var errSocksBadRequest = errors.New("bad socks request")

func (b *anyTLSBridge) handleSocks(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != socksVer {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{socksVer, 0}); err != nil { // NO AUTH
		return
	}
	req := make([]byte, 3)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != socksVer {
		return
	}
	dest, err := readSocksAddr(c)
	if err != nil {
		return
	}
	switch req[1] {
	case socksCmdConnect:
		remote, err := b.client.CreateProxy(b.ctx, dest)
		if err != nil {
			c.Write([]byte{socksVer, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
			return
		}
		if !b.track(remote) {
			return
		}
		defer b.untrack(remote)
		if _, err := c.Write([]byte{socksVer, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		c.SetDeadline(time.Time{})
		relayTCP(c, remote)
	case socksCmdUDPAssoc:
		b.handleUDPAssociate(c)
	default:
		c.Write([]byte{socksVer, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // command not supported
	}
}

// readSocksAddr 读 ATYP + ADDR + PORT。
func readSocksAddr(r io.Reader) (M.Socksaddr, error) {
	t := make([]byte, 1)
	if _, err := io.ReadFull(r, t); err != nil {
		return M.Socksaddr{}, err
	}
	var host string
	switch t[0] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return M.Socksaddr{}, err
		}
		host = net.IP(ip).String()
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return M.Socksaddr{}, err
		}
		host = net.IP(ip).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return M.Socksaddr{}, err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return M.Socksaddr{}, err
		}
		host = string(name)
	default:
		return M.Socksaddr{}, errSocksBadRequest
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return M.Socksaddr{}, err
	}
	return M.ParseSocksaddrHostPort(host, binary.BigEndian.Uint16(p)), nil
}

// appendSocksAddr 写 ATYP + ADDR + PORT。
func appendSocksAddr(dst []byte, a M.Socksaddr) []byte {
	if a.IsFqdn() {
		dst = append(dst, 3, byte(len(a.Fqdn)))
		dst = append(dst, a.Fqdn...)
	} else if ip := a.Addr.Unmap(); ip.Is4() {
		b := ip.As4()
		dst = append(dst, 1)
		dst = append(dst, b[:]...)
	} else {
		b := a.Addr.As16()
		dst = append(dst, 4)
		dst = append(dst, b[:]...)
	}
	return binary.BigEndian.AppendUint16(dst, a.Port)
}

func relayTCP(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// 一侧结束后给另一侧一点时间收尾（半关闭），再整体关闭
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()
	a.Close()
	b.Close()
}

// anyTLSStreamDialer 让 uot.Client 经 AnyTLS 流拨号（UDP-over-TCP 用）。
type anyTLSStreamDialer struct{ b *anyTLSBridge }

func (d anyTLSStreamDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, fmt.Errorf("unsupported network %s", network)
	}
	return d.b.client.CreateProxy(ctx, destination)
}

func (d anyTLSStreamDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("ListenPacket not supported")
}

// handleUDPAssociate SOCKS5 UDP ASSOCIATE：本地 UDP 口收发 SOCKS UDP 报文，
// 经 UDP-over-TCP v2 走一条 AnyTLS 流。控制连接断开即结束。
func (b *anyTLSBridge) handleUDPAssociate(ctrl net.Conn) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		ctrl.Write([]byte{socksVer, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if !b.track(pc) {
		return
	}
	defer b.untrack(pc)
	reply := []byte{socksVer, 0, 0}
	reply = appendSocksAddr(reply, M.SocksaddrFromNet(pc.LocalAddr()))
	if _, err := ctrl.Write(reply); err != nil {
		return
	}
	ctrl.SetDeadline(time.Time{})

	// UoT 请求头里必须带一个合法目标（非 connect 模式下服务端只当参考），
	// 所以等第一个报文到了、拿它的目标去建 UoT 流。
	var remote net.PacketConn
	defer func() {
		if remote != nil {
			b.untrack(remote)
		}
	}()

	// 控制连接关闭 → 结束整个关联
	go func() {
		io.Copy(io.Discard, ctrl)
		pc.Close()
	}()

	var (
		clientMu   sync.Mutex
		clientAddr net.Addr
	)
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[2] != 0 { // 不支持分片
			continue
		}
		r := &byteReader{b: buf[3:n]}
		dest, err := readSocksAddr(r)
		if err != nil {
			continue
		}
		clientMu.Lock()
		clientAddr = from
		clientMu.Unlock()
		if remote == nil {
			uc := &uot.Client{Dialer: anyTLSStreamDialer{b}, Version: uot.Version}
			rc, err := uc.ListenPacket(b.ctx, dest)
			if err != nil {
				return
			}
			if !b.track(rc) {
				return
			}
			remote = rc
			// 远端 → 本地客户端
			go func() {
				rb := make([]byte, 65535)
				for {
					n, src, err := rc.ReadFrom(rb)
					if err != nil {
						pc.Close()
						return
					}
					clientMu.Lock()
					to := clientAddr
					clientMu.Unlock()
					pkt := appendSocksAddr([]byte{0, 0, 0}, M.SocksaddrFromNet(src))
					pkt = append(pkt, rb[:n]...)
					pc.WriteTo(pkt, to)
				}
			}()
		}
		if _, err := remote.WriteTo(r.rest(), dest); err != nil {
			return
		}
	}
}

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func (r *byteReader) rest() []byte { return r.b[r.i:] }
