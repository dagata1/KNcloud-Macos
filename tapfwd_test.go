package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// ------------------------- 测试拓扑 -------------------------
//
//  client stack (10.0.0.2) ⇄ channel ⇄ channel ⇄ tapForwarder stack（混杂模式）
//                                                   ├─ TCP → fake SOCKS5 → echo server
//                                                   ├─ UDP → fake SOCKS5 UDP ASSOCIATE（回显）
//                                                   └─ UDP:53 → fake DNS upstream

func shuttle(ctx context.Context, from, to *channel.Endpoint) {
	for {
		pkt := from.ReadContext(ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		proto := pkt.NetworkProtocolNumber
		pkt.DecRef()
		np := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
		to.InjectInbound(proto, np)
		np.DecRef()
	}
}

type fwdHarness struct {
	t       *testing.T
	client  *stack.Stack
	fwd     *tapForwarder
	socks   *fakeSocks
	dnsAddr string
	cancel  context.CancelFunc
}

func newFwdHarness(t *testing.T, cfg tapForwarderConfig) *fwdHarness {
	t.Helper()
	h := &fwdHarness{t: t, socks: startFakeSocks(t)}
	h.dnsAddr = startFakeDNS(t)
	cfg.SocksAddr = h.socks.addr
	cfg.DNSUpstream = h.dnsAddr
	cfg.DNSAddr = tunDnsAddr

	cEP := channel.New(4096, tapMTU, "")
	fEP := channel.New(4096, tapMTU, "")
	f, err := newTapForwarder(fEP, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.fwd = f

	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := cs.CreateNIC(1, cEP); err != nil {
		t.Fatal(err)
	}
	cs.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}).WithPrefix(),
	}, stack.AddressProperties{})
	cs.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	h.client = cs

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go shuttle(ctx, cEP, fEP)
	go shuttle(ctx, fEP, cEP)
	t.Cleanup(func() {
		f.stop(2 * time.Second)
		cancel()
		cs.Destroy()
		h.socks.close()
	})
	return h
}

func (h *fwdHarness) dialTCP(ip [4]byte, port uint16) *gonet.TCPConn {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, h.client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ip), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		h.t.Fatalf("dial %v:%d through TUN: %v", ip, port, err)
	}
	return c
}

func (h *fwdHarness) dialUDP(ip [4]byte, port uint16) *gonet.UDPConn {
	h.t.Helper()
	c, err := gonet.DialUDP(h.client, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ip), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		h.t.Fatalf("dial udp: %v", err)
	}
	return c
}

// ------------------------- fake SOCKS5 -------------------------

type fakeSocks struct {
	addr      string
	ln        net.Listener
	echo      string // TCP CONNECT 一律转到这个回显服务
	mu        sync.Mutex
	dsts      []string
	ctrlOpen  atomic.Int64 // 打开中的 UDP ASSOCIATE 控制连接
	udpAssocs atomic.Int64
}

func startFakeSocks(t *testing.T) *fakeSocks {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocks{addr: ln.Addr().String(), ln: ln, echo: echo.Addr().String()}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *fakeSocks) close() { s.ln.Close() }

func (s *fakeSocks) serve(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	cmd, atyp := buf[1], buf[3]
	var dst string
	switch atyp {
	case 1:
		io.ReadFull(c, buf[:6])
		dst = net.JoinHostPort(net.IP(buf[:4]).String(), itoa(int(binary.BigEndian.Uint16(buf[4:6]))))
	case 4:
		io.ReadFull(c, buf[:18])
		dst = net.JoinHostPort(net.IP(buf[:16]).String(), itoa(int(binary.BigEndian.Uint16(buf[16:18]))))
	default:
		return
	}
	s.mu.Lock()
	s.dsts = append(s.dsts, dst)
	s.mu.Unlock()
	switch cmd {
	case 1: // CONNECT
		up, err := net.Dial("tcp", s.echo)
		if err != nil {
			c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		go func() { io.Copy(up, c); up.(*net.TCPConn).CloseWrite() }()
		io.Copy(c, up)
	case 3: // UDP ASSOCIATE：回显，头原样带回
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer pc.Close()
		s.udpAssocs.Add(1)
		s.ctrlOpen.Add(1)
		defer s.ctrlOpen.Add(-1)
		port := pc.LocalAddr().(*net.UDPAddr).Port
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		go func() {
			b := make([]byte, 65535)
			for {
				n, from, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				pc.WriteTo(b[:n], from)
			}
		}()
		io.Copy(io.Discard, c) // 控制连接保持到对端关闭
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func intStr(n int) string { return strconv.Itoa(n) }

// startFakeDNS 收到什么就回 "ANS:"+原文
func startFakeDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("ANS:"), b[:n]...), from)
		}
	}()
	return pc.LocalAddr().String()
}

// ------------------------- 测试 -------------------------

// 混杂模式：目的地址是任意公网 IP 的包也要被接收并转发（#1）
func TestForwarderTCPAnyDestination(t *testing.T) {
	h := newFwdHarness(t, tapForwarderConfig{})
	c := h.dialTCP([4]byte{203, 0, 113, 7}, 443)
	defer c.Close()
	msg := []byte("hello through tun")
	c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %q %v", got, err)
	}
	h.socks.mu.Lock()
	defer h.socks.mu.Unlock()
	if len(h.socks.dsts) == 0 || h.socks.dsts[0] != "203.0.113.7:443" {
		t.Fatalf("SOCKS CONNECT target = %v, want original destination 203.0.113.7:443", h.socks.dsts)
	}
}

// 双向同时大流量：收发并行、无死锁，数据完整（#2）
func TestForwarderTCPBidirectionalBulk(t *testing.T) {
	h := newFwdHarness(t, tapForwarderConfig{})
	const size = 16 << 20
	payload := make([]byte, size)
	rand.Read(payload)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := h.dialTCP([4]byte{198, 51, 100, byte(i + 1)}, 80)
			defer c.Close()
			errc := make(chan error, 1)
			go func() {
				_, err := c.Write(payload)
				c.CloseWrite()
				errc <- err
			}()
			c.SetReadDeadline(time.Now().Add(60 * time.Second))
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("conn %d: got %d bytes err=%v", i, len(got), err)
			}
			if err := <-errc; err != nil {
				t.Errorf("conn %d write: %v", i, err)
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("bulk transfer deadlocked")
	}
}

// DNS 中继：发往 198.18.0.2:53 的查询立即由上游应答，无 ~1s 超时（#3）
func TestForwarderDNSRelay(t *testing.T) {
	h := newFwdHarness(t, tapForwarderConfig{DNSIdle: 300 * time.Millisecond})
	for i := 0; i < 5; i++ {
		c := h.dialUDP([4]byte{198, 18, 0, 2}, 53)
		start := time.Now()
		q := []byte("query-" + intStr(i))
		c.Write(q)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 512)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != "ANS:"+string(q) {
			t.Fatalf("dns %d: %q %v", i, b[:n], err)
		}
		if d := time.Since(start); d > 300*time.Millisecond {
			t.Fatalf("dns answer took %v", d)
		}
		c.Close()
	}
	// 空闲超时后 DNS 流全部回收
	deadline := time.Now().Add(3 * time.Second)
	for h.fwd.dnsActive.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := h.fwd.dnsActive.Load(); n != 0 {
		t.Fatalf("%d DNS flows still active after idle timeout", n)
	}
}

// UDP：经 SOCKS5 UDP ASSOCIATE 往返；空闲超时后流、关联、控制连接全部拆除（#9）
func TestForwarderUDPTeardownOnIdle(t *testing.T) {
	h := newFwdHarness(t, tapForwarderConfig{UDPIdle: 400 * time.Millisecond})
	c := h.dialUDP([4]byte{203, 0, 113, 9}, 3478)
	c.Write([]byte("stun"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 512)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "stun" {
		t.Fatalf("udp echo: %q %v", b[:n], err)
	}
	if h.fwd.udpActive.Load() != 1 || h.socks.ctrlOpen.Load() != 1 {
		t.Fatalf("active flows=%d ctrl=%d", h.fwd.udpActive.Load(), h.socks.ctrlOpen.Load())
	}
	deadline := time.Now().Add(3 * time.Second)
	for (h.fwd.udpActive.Load() != 0 || h.socks.ctrlOpen.Load() != 0) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.fwd.udpActive.Load() != 0 || h.socks.ctrlOpen.Load() != 0 {
		t.Fatalf("after idle: flows=%d ctrl=%d, want 0/0", h.fwd.udpActive.Load(), h.socks.ctrlOpen.Load())
	}
	// 再发一包：新流照常建立
	c.Write([]byte("again"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.Read(b); err != nil || string(b[:n]) != "again" {
		t.Fatalf("udp after teardown: %q %v", b[:n], err)
	}
	c.Close()
}

// stop：活跃 TCP/UDP 流全部断开，协程全部退出（换节点时的「重启转发」）
func TestForwarderStopReleasesEverything(t *testing.T) {
	h := newFwdHarness(t, tapForwarderConfig{UDPIdle: time.Minute})
	tc := h.dialTCP([4]byte{203, 0, 113, 1}, 80)
	tc.Write([]byte("x"))
	b := make([]byte, 1)
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadFull(tc, b)
	uc := h.dialUDP([4]byte{203, 0, 113, 2}, 9000)
	uc.Write([]byte("y"))
	uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	uc.Read(b)
	if h.fwd.tcpActive.Load() != 1 || h.fwd.udpActive.Load() != 1 {
		t.Fatalf("tcp=%d udp=%d before stop", h.fwd.tcpActive.Load(), h.fwd.udpActive.Load())
	}
	if !h.fwd.stop(3 * time.Second) {
		t.Fatal("forwarder goroutines did not exit within 3s")
	}
	if h.fwd.tcpActive.Load() != 0 || h.fwd.udpActive.Load() != 0 {
		t.Fatalf("tcp=%d udp=%d after stop", h.fwd.tcpActive.Load(), h.fwd.udpActive.Load())
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.socks.ctrlOpen.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.socks.ctrlOpen.Load() != 0 {
		t.Fatal("UDP ASSOCIATE control connection leaked after stop")
	}
}

func TestStripSocksUDPHeader(t *testing.T) {
	h := socksUDPHeader(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 53})
	p, ok := stripSocksUDPHeader(append(h, 'x'))
	if !ok || string(p) != "x" {
		t.Fatalf("v4: %q %v", p, ok)
	}
	h6 := socksUDPHeader(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53})
	if p, ok := stripSocksUDPHeader(append(h6, 'y')); !ok || string(p) != "y" {
		t.Fatalf("v6: %q %v", p, ok)
	}
	if _, ok := stripSocksUDPHeader([]byte{0, 0, 1, 1}); ok {
		t.Fatal("fragmented datagram must be dropped")
	}
}

// UDP 必须走专用（不嗅探）的 SOCKS 入站，TCP 仍走 socks-in（Xray QUIC 嗅探器会 panic）
func TestForwarderUDPUsesDedicatedInbound(t *testing.T) {
	h := newFwdHarness(t, tapForwarderConfig{UDPIdle: 2 * time.Second})
	udpSocks := startFakeSocks(t)
	h.fwd.cfg.SocksUDP = udpSocks.addr
	c := h.dialUDP([4]byte{203, 0, 113, 10}, 443)
	defer c.Close()
	c.Write([]byte("quic-initial"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 512)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "quic-initial" {
		t.Fatalf("udp echo: %q %v", b[:n], err)
	}
	if udpSocks.ctrlOpen.Load() != 1 || h.socks.ctrlOpen.Load() != 0 {
		t.Fatalf("UDP associate went to the wrong inbound: dedicated=%d socks-in=%d", udpSocks.ctrlOpen.Load(), h.socks.ctrlOpen.Load())
	}
}
