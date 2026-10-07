package main

// tapfwd.go —— TUN 转发运行时：gVisor 用户态协议栈 + TCP/UDP/DNS 转发。
//
// 与网卡解耦：newTapForwarder 接受任意 stack.LinkEndpoint，生产环境传 wintun
// 链路端点，单测传 gVisor channel 端点（不需要管理员权限、不碰系统网络）。

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tapForwarderConfig 转发运行时参数
type tapForwarderConfig struct {
	SocksAddr   string        // Xray SOCKS5 入站，如 127.0.0.1:10808
	SocksUDP    string        // UDP ASSOCIATE 用的 SOCKS5 入站（不嗅探）；空 = SocksAddr
	DNSAddr     string        // 劫持 DNS 地址（198.18.0.2）：发往它的查询转给 DNSUpstream
	DNSUpstream string        // 如 223.5.5.5:53
	BindIdx     uint32        // DNS 上游 socket 绑定的物理网卡（0 = 不绑定，单测用）
	UDPIdle     time.Duration // 普通 UDP 流空闲超时
	DNSIdle     time.Duration // DNS 流空闲超时
}

func (c *tapForwarderConfig) defaults() {
	if c.UDPIdle == 0 {
		c.UDPIdle = 60 * time.Second
	}
	if c.DNSIdle == 0 {
		c.DNSIdle = 10 * time.Second
	}
	if c.DNSUpstream == "" {
		c.DNSUpstream = "223.5.5.5:53"
	}
	if c.DNSAddr == "" {
		c.DNSAddr = tunDnsAddr
	}
}

// tapForwarder TUN 开启期间的转发运行时：gvisor 协议栈 + 各转发协程
type tapForwarder struct {
	stack  *stack.Stack
	linkEP stack.LinkEndpoint
	cfg    tapForwarderConfig
	stopCh chan struct{}
	wg     sync.WaitGroup

	mu      sync.Mutex
	closers map[io.Closer]struct{} // 活跃连接/流：stop 时统一关闭
	stopped bool

	tcpActive atomic.Int64
	udpActive atomic.Int64
	dnsActive atomic.Int64
}

// tcpCopyBufSize 每方向的拷贝缓冲：巨型帧下 32KB 太小，系统调用次数翻倍
const tcpCopyBufSize = 256 << 10

var tcpCopyBufPool = sync.Pool{New: func() any { b := make([]byte, tcpCopyBufSize); return &b }}

// newTapForwarder 在 link 上建 gVisor 协议栈并挂好 TCP/UDP 转发器。
func newTapForwarder(link stack.LinkEndpoint, cfg tapForwarderConfig) (*tapForwarder, error) {
	cfg.defaults()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// 吞吐：SACK + 接收缓冲自动调节 + 大缓冲 + cubic（gVisor 默认 reno、SACK 关）
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20})
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20})
	cc := tcpip.CongestionControlOption("cubic")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &cc)
	// 关掉 RACK（连带 TLP）：这版 gVisor 的探测超时 PTO = 2×SRTT、没有 10ms 下限，TUN 两端在
	// 同一台机器上，SRTT 只有几十到几百微秒，Windows 的 ACK 稍晚一点（延迟确认、调度抖动）就触发
	// TLP + RACK 判丢，大量重传早已确认的数据、拥塞窗口反复减半。实测（TAP 后端）：33% 的段被
	// 重传、抓包里全是 D-SACK，下载只有 5~50KB/s，而同节点 SOCKS 1MB/s。
	// 退回经典的三次重复 ACK + SACK 恢复（RTO 下限 200ms）。
	rec := tcpip.TCPRecovery(0)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rec)

	if err := s.CreateNIC(1, link); err != nil {
		s.Destroy()
		return nil, errors.New("gvisor CreateNIC: " + err.String())
	}
	// 关键：NIC 没有配置任何地址，默认只收「目的地址属于本机」的包，而路由吸进 TUN 的
	// 包目的地址五花八门 —— 不开混杂模式全部被当作 InvalidDestination 丢弃。
	// Spoofing 允许以任意源地址回包（回包源 = 原目的地址）。
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	f := &tapForwarder{
		stack:   s,
		linkEP:  link,
		cfg:     cfg,
		stopCh:  make(chan struct{}),
		closers: map[io.Closer]struct{}{},
	}

	tcpFwd := tcp.NewForwarder(s, 0, 4096, f.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, f.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return f, nil
}

// track 登记一个需要在 stop 时关闭的对象；已停止则立即关闭并返回 false。
func (f *tapForwarder) track(c io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		c.Close()
		return false
	}
	f.closers[c] = struct{}{}
	return true
}

func (f *tapForwarder) untrack(c io.Closer) {
	f.mu.Lock()
	delete(f.closers, c)
	f.mu.Unlock()
}

// stop 关闭全部连接与协议栈，最多等 wait 让协程退出；返回是否全部退出。
func (f *tapForwarder) stop(wait time.Duration) bool {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return true
	}
	f.stopped = true
	cs := f.closers
	f.closers = map[io.Closer]struct{}{}
	f.mu.Unlock()
	close(f.stopCh)
	for c := range cs {
		c.Close()
	}
	// Destroy 会 Abort 全部端点（向客户端发 RST）并移除 NIC
	f.stack.Destroy()
	done := make(chan struct{})
	go func() { f.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(wait):
		return false
	}
}

// ------------------------- TCP -------------------------

func (f *tapForwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(false)
	conn := gonet.NewTCPConn(&wq, ep)
	if !f.track(conn) {
		return
	}
	f.wg.Add(1)
	f.tcpActive.Add(1)
	go func() {
		defer f.wg.Done()
		defer f.tcpActive.Add(-1)
		defer f.untrack(conn)
		defer conn.Close()
		dst := &net.TCPAddr{IP: addrToNetIP(id.LocalAddress), Port: int(id.LocalPort)}
		up, err := socksDialTCP(f.cfg.SocksAddr, dst, 15*time.Second)
		if err != nil {
			return
		}
		if !f.track(up) {
			return
		}
		defer f.untrack(up)
		defer up.Close()
		if tc, ok := up.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		done := make(chan struct{}, 1)
		go func() {
			pipeHalf(up, conn)
			done <- struct{}{}
		}()
		pipeHalf(conn, up)
		<-done
	}()
}

type closeWriter interface{ CloseWrite() error }

// pipeHalf 单向拷贝 src → dst，src 读完后对 dst 半关闭（保持另一方向继续传输）。
func pipeHalf(dst io.Writer, src io.Reader) {
	bp := tcpCopyBufPool.Get().(*[]byte)
	// 包一层屏蔽 ReaderFrom/WriterTo，确保用上大缓冲
	_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *bp)
	tcpCopyBufPool.Put(bp)
	if cw, ok := dst.(closeWriter); ok && err == nil {
		cw.CloseWrite()
		return
	}
	// 出错（RST/超时）：两端都关，另一方向随即退出
	if c, ok := dst.(io.Closer); ok {
		c.Close()
	}
	if c, ok := src.(io.Closer); ok {
		c.Close()
	}
}

// ------------------------- UDP -------------------------

// udpFlow 一条 UDP 流（TUN 内一个五元组）的全部资源，teardown 一次性关闭。
type udpFlow struct {
	mu      sync.Mutex
	closed  bool
	closers []io.Closer
	last    atomic.Int64 // 最近一次收发的时间（UnixNano）
}

// add 把资源挂到流上；流已关闭则立即关闭该资源并返回 false。
func (u *udpFlow) add(c io.Closer) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		c.Close()
		return false
	}
	u.closers = append(u.closers, c)
	return true
}

func (u *udpFlow) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	cs := u.closers
	u.closers = nil
	u.mu.Unlock()
	for _, c := range cs {
		c.Close()
	}
	return nil
}

func (u *udpFlow) touch() { u.last.Store(time.Now().UnixNano()) }

// idleFor 距最近一次活动的时长
func (u *udpFlow) idleFor() time.Duration {
	return time.Since(time.Unix(0, u.last.Load()))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded)
}

// readIdle 带空闲超时地读：每次读设置 idle 的截止时间，超时但流在 idle 内另一方向
// 有过活动时继续等；真正空闲满 idle 返回错误。
func readIdle(flow *udpFlow, idle time.Duration, setDeadline func(time.Time) error, read func() (int, error)) (int, error) {
	for {
		setDeadline(time.Now().Add(idle))
		n, err := read()
		if err == nil {
			flow.touch()
			return n, nil
		}
		if isTimeout(err) && flow.idleFor() < idle {
			continue
		}
		return 0, err
	}
}

func (f *tapForwarder) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, uerr := r.CreateEndpoint(&wq)
	if uerr != nil {
		return
	}
	pc := gonet.NewUDPConn(f.stack, &wq, ep)
	dst := &net.UDPAddr{IP: addrToNetIP(id.LocalAddress), Port: int(id.LocalPort)}
	flow := &udpFlow{closers: []io.Closer{pc}}
	flow.touch()
	if !f.track(flow) {
		return
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer f.untrack(flow)
		defer flow.Close()
		if dst.Port == 53 {
			f.dnsActive.Add(1)
			defer f.dnsActive.Add(-1)
			f.relayDNS(flow, pc, dst)
			return
		}
		f.udpActive.Add(1)
		defer f.udpActive.Add(-1)
		f.relayUDPSocks(flow, pc, dst)
	}()
}

// relayDNS DNS 通道：TUN 内的 UDP:53 查询经绑定物理网卡的 socket 直连上游。
// 发往劫持地址（198.18.0.2）的查询转给公共 DNS；发往其他 DNS 服务器的原样转发。
// 阻塞到流结束（空闲 DNSIdle 或任一方向出错）。
func (f *tapForwarder) relayDNS(flow *udpFlow, pc *gonet.UDPConn, dst *net.UDPAddr) {
	upstream := dst.String()
	if dst.IP.Equal(net.ParseIP(f.cfg.DNSAddr)) {
		upstream = f.cfg.DNSUpstream
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	if f.cfg.BindIdx != 0 {
		d.Control = bindToIfaceControl(f.cfg.BindIdx)
	}
	uc, err := d.Dial("udp", upstream)
	if err != nil || !flow.add(uc) {
		return
	}
	f.relayPair(flow, f.cfg.DNSIdle, pc, uc, func(b []byte) []byte { return b }, func(b []byte) ([]byte, bool) { return b, true })
}

// relayUDPSocks 非 DNS 的 UDP（QUIC/游戏/语音等）：SOCKS5 UDP ASSOCIATE 经 Xray 转发。
func (f *tapForwarder) relayUDPSocks(flow *udpFlow, pc *gonet.UDPConn, dst *net.UDPAddr) {
	addr := f.cfg.SocksUDP
	if addr == "" {
		addr = f.cfg.SocksAddr
	}
	ch, err := socksDialUDP(addr, 15*time.Second)
	if err != nil {
		return
	}
	if !flow.add(ch.udp) || !flow.add(ch.control) {
		ch.control.Close()
		return
	}
	// 控制连接断开（Xray 关闭关联）即结束整条流
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		buf := make([]byte, 1)
		for {
			if _, err := ch.control.Read(buf); err != nil {
				flow.Close()
				return
			}
		}
	}()
	hdr := socksUDPHeader(dst)
	f.relayPair(flow, f.cfg.UDPIdle, pc, ch.udp,
		func(b []byte) []byte { return append(append(make([]byte, 0, len(hdr)+len(b)), hdr...), b...) },
		func(b []byte) ([]byte, bool) { return stripSocksUDPHeader(b) })
}

// relayPair 双向搬运：pc（TUN 内客户端）⇄ up（上游 socket）。
// 任一方向出错或整条流空闲满 idle 即 teardown；阻塞到两个方向都退出。
func (f *tapForwarder) relayPair(flow *udpFlow, idle time.Duration, pc *gonet.UDPConn, up net.Conn,
	wrap func([]byte) []byte, unwrap func([]byte) ([]byte, bool)) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer flow.Close()
		buf := make([]byte, 65535)
		for {
			n, err := readIdle(flow, idle, up.SetReadDeadline, func() (int, error) { return up.Read(buf) })
			if err != nil {
				return
			}
			payload, ok := unwrap(buf[:n])
			if !ok {
				continue
			}
			if _, err := pc.Write(payload); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, err := readIdle(flow, idle, pc.SetReadDeadline, func() (int, error) { return pc.Read(buf) })
		if err != nil {
			break
		}
		if _, err := up.Write(wrap(buf[:n])); err != nil {
			break
		}
	}
	flow.Close()
	<-done
}

// stripSocksUDPHeader 去掉 SOCKS5 UDP 转发头（RSV RSV FRAG ATYP ADDR PORT），返回载荷。
func stripSocksUDPHeader(b []byte) ([]byte, bool) {
	if len(b) < 4 || b[2] != 0 { // 不支持分片
		return nil, false
	}
	switch b[3] {
	case 0x01:
		if len(b) < 10 {
			return nil, false
		}
		return b[10:], true
	case 0x04:
		if len(b) < 22 {
			return nil, false
		}
		return b[22:], true
	case 0x03:
		if len(b) < 5 || len(b) < 7+int(b[4]) {
			return nil, false
		}
		return b[7+int(b[4]):], true
	}
	return nil, false
}
