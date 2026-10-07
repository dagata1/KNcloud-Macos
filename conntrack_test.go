package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
)

// startEchoServer 起一个本地 TCP 回显服务，充当「节点服务器 / 目标站点」。
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法绑定本地端口，跳过: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// newSocksCore 起一个 SOCKS5 入站 + freedom(proxy) 出站的内核，返回实例与入站端口。
func newSocksCore(t *testing.T) (*xcore.Instance, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法绑定本地端口，跳过: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf(`{
	  "inbounds": [{"tag":"socks-in","port":%d,"listen":"127.0.0.1","protocol":"socks",
	                "settings":{"auth":"noauth","udp":false}}],
	  "outbounds": [{"tag":"%s","protocol":"freedom","settings":{}},
	                {"tag":"direct","protocol":"freedom","settings":{}}]
	}`, port, proxyOutboundTag)
	pb, err := serial.DecodeJSONConfig(bytes.NewReader([]byte(cfg)))
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	full, err := pb.Build()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	inst, err := xcore.New(full)
	if err != nil {
		t.Fatalf("new instance: %v", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		t.Fatalf("start instance: %v", err)
	}
	t.Cleanup(func() { inst.Close(); outboundConnTracker.Forget(inst) })
	time.Sleep(100 * time.Millisecond)
	return inst, port
}

// socksDial 通过 SOCKS5 入站建立到 target 的 TCP 隧道（最小实现，仅 noauth + IPv4）。
func socksDial(t *testing.T, socksPort int, target string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	host, portStr, _ := net.SplitHostPort(target)
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	ip := net.ParseIP(host).To4()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		t.Fatalf("socks greeting: %v %v", resp, err)
	}
	req := []byte{5, 1, 0, 1}
	req = append(req, ip...)
	req = binary.BigEndian.AppendUint16(req, uint16(p))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0 {
		t.Fatalf("socks connect: %v %v", rep, err)
	}
	c.SetDeadline(time.Time{})
	return c
}

func echoOnce(c net.Conn, msg string) error {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}

// waitClosed 等待隧道被对端关闭（读到 EOF / 连接错误）。
func waitClosed(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 64)
	for {
		_, err := c.Read(buf)
		if err != nil {
			ne, ok := err.(net.Error)
			return !(ok && ne.Timeout())
		}
	}
}

func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestTrackerIsRegistered 记账拨号器必须真的被装进 Xray，否则热切换清不掉旧连接。
func TestTrackerIsRegistered(t *testing.T) {
	echo := startEchoServer(t)
	inst, port := newSocksCore(t)
	c := socksDial(t, port, echo)
	defer c.Close()
	if err := echoOnce(c, "hello"); err != nil {
		t.Fatalf("隧道应可用: %v", err)
	}
	if !waitFor(func() bool { return outboundConnTracker.count(inst) == 1 }, 2*time.Second) {
		t.Fatalf("proxy 出站连接应被记账，实际 %d", outboundConnTracker.count(inst))
	}
	c.Close()
	if !waitFor(func() bool { return outboundConnTracker.count(inst) == 0 }, 3*time.Second) {
		t.Fatalf("连接关闭后应从记账中移除，实际仍有 %d", outboundConnTracker.count(inst))
	}
}

// TestHotSwapClosesExistingConnections 换节点后，挂在旧出站上的存量（keep-alive）连接
// 必须被切断，客户端重连才会走新节点；入站监听保持可用。
func TestHotSwapClosesExistingConnections(t *testing.T) {
	echo := startEchoServer(t)
	inst, port := newSocksCore(t)
	a := &App{xrayInst: inst}

	c := socksDial(t, port, echo)
	defer c.Close()
	if err := echoOnce(c, "before"); err != nil {
		t.Fatalf("切换前隧道应可用: %v", err)
	}
	waitFor(func() bool { return outboundConnTracker.count(inst) == 1 }, 2*time.Second)

	node := NodeItem{
		Name: "new", Protocol: "VLESS", Address: "127.0.0.1", Port: 1,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Security: "none", Network: "tcp",
	}
	if err := a.hotSwapProxyOutboundLocked(node); err != nil {
		t.Fatalf("热切换应当成功: %v", err)
	}
	if !waitClosed(c, 3*time.Second) {
		t.Fatal("旧节点上的存量连接应在热切换后被关闭")
	}
	if n := outboundConnTracker.count(inst); n != 0 {
		t.Fatalf("旧代际连接应全部清掉，仍有 %d", n)
	}
	// 入站监听不受影响：仍能完成 SOCKS 握手（新出站指向不可达端口，不要求数据可通）。
	c2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("热切换后入站监听应仍在: %v", err)
	}
	c2.Close()
}

// TestHotSwapKeepsOtherInstancesAndDirect 清扫只针对主内核的 proxy 出站：
// 另一个实例（如测速用的临时内核）以及 direct 出站上的连接不受影响。
func TestHotSwapKeepsOtherInstances(t *testing.T) {
	echo := startEchoServer(t)
	main, mainPort := newSocksCore(t)
	other, otherPort := newSocksCore(t)

	cm := socksDial(t, mainPort, echo)
	defer cm.Close()
	co := socksDial(t, otherPort, echo)
	defer co.Close()
	if err := echoOnce(cm, "m"); err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(co, "o"); err != nil {
		t.Fatal(err)
	}
	waitFor(func() bool { return outboundConnTracker.count(other) == 1 }, 2*time.Second)

	a := &App{xrayInst: main}
	node := NodeItem{
		Name: "new", Protocol: "VLESS", Address: "127.0.0.1", Port: 1,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Security: "none", Network: "tcp",
	}
	if err := a.hotSwapProxyOutboundLocked(node); err != nil {
		t.Fatalf("热切换应当成功: %v", err)
	}
	if !waitClosed(cm, 3*time.Second) {
		t.Fatal("主内核的旧连接应被关闭")
	}
	if err := echoOnce(co, "still-alive"); err != nil {
		t.Fatalf("其他实例上的连接不应被关闭: %v", err)
	}
}

// TestHotSwapRejectedNodeKeepsConnections 新节点被拒（未进入提交阶段）时，
// 现网连接原样保留。
func TestHotSwapRejectedNodeKeepsConnections(t *testing.T) {
	echo := startEchoServer(t)
	inst, port := newSocksCore(t)
	a := &App{xrayInst: inst}
	c := socksDial(t, port, echo)
	defer c.Close()
	if err := echoOnce(c, "x"); err != nil {
		t.Fatal(err)
	}
	if err := a.hotSwapProxyOutboundLocked(NodeItem{Name: "bad", Protocol: "bogus"}); err == nil {
		t.Fatal("bogus 协议应被拒绝")
	}
	if err := echoOnce(c, "still-alive"); err != nil {
		t.Fatalf("被拒的切换不应影响现有连接: %v", err)
	}
}

// fakeDialer 模拟一个慢拨号器，用于验证「切换前开始、切换后才拨通」的连接也会被关掉。
type fakeDialer struct {
	release chan struct{}
	mu      sync.Mutex
	conns   []net.Conn
}

func (f *fakeDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	if f.release != nil {
		<-f.release
	}
	a, b := net.Pipe()
	f.mu.Lock()
	f.conns = append(f.conns, b)
	f.mu.Unlock()
	return a, nil
}

func (f *fakeDialer) DestIpAddress() net.IP { return nil }

type testInstKey struct{}

// trackerCtx 构造带实例与出站 tag 的拨号 ctx（core 包不导出写入实例的函数，测试里用自己的 key）。
func trackerCtx(inst *xcore.Instance, tag string) context.Context {
	ctx := context.WithValue(context.Background(), testInstKey{}, inst)
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: tag}})
}

func newTestTracker(base internet.SystemDialer) *connTracker {
	tr := newConnTracker(base, proxyOutboundTag)
	tr.instOf = func(ctx context.Context) *xcore.Instance {
		inst, _ := ctx.Value(testInstKey{}).(*xcore.Instance)
		return inst
	}
	return tr
}

func TestTrackerInFlightDialFromOldGenerationIsClosed(t *testing.T) {
	inst, _ := newSocksCore(t)
	fd := &fakeDialer{release: make(chan struct{})}
	tr := newTestTracker(fd)
	dest := xnet.TCPDestination(xnet.LocalHostIP, 1)

	done := make(chan error, 1)
	go func() {
		_, err := tr.Dial(trackerCtx(inst, proxyOutboundTag), nil, dest, nil)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // 让拨号先取到旧代际
	cut := tr.Advance()
	tr.CloseBefore(inst, cut)
	close(fd.release)
	if err := <-done; err == nil {
		t.Fatal("切换前开始的拨号在切换后拨通，应被立即关闭并报错")
	}
	if tr.count(inst) != 0 {
		t.Fatal("被拒的旧代际连接不应留在记账里")
	}

	// 新代际的拨号不受影响。
	conn, err := tr.Dial(trackerCtx(inst, proxyOutboundTag), nil, dest, nil)
	if err != nil {
		t.Fatalf("新代际拨号应成功: %v", err)
	}
	defer conn.Close()
	if tr.count(inst) != 1 {
		t.Fatal("新代际连接应被记账")
	}
}

func TestTrackerIgnoresOtherTagsAndUDP(t *testing.T) {
	inst, _ := newSocksCore(t)
	fd := &fakeDialer{}
	tr := newTestTracker(fd)

	c, err := tr.Dial(trackerCtx(inst, "direct"), nil, xnet.TCPDestination(xnet.LocalHostIP, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, wrapped := c.(*trackedConn); wrapped {
		t.Fatal("direct 出站的连接不应被包装 / 追踪")
	}
	u, err := tr.Dial(trackerCtx(inst, proxyOutboundTag), nil, xnet.UDPDestination(xnet.LocalHostIP, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, wrapped := u.(*trackedConn); wrapped {
		t.Fatal("UDP 连接不应被包装（quic/splithttp 依赖原始类型）")
	}
	// 没有实例信息的拨号（如 mux worker 自建的 ctx）也不追踪。
	n, err := tr.Dial(session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: proxyOutboundTag}}),
		nil, xnet.TCPDestination(xnet.LocalHostIP, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, wrapped := n.(*trackedConn); wrapped {
		t.Fatal("ctx 中没有实例时不应追踪")
	}
	if tr.count(inst) != 0 {
		t.Fatal("以上连接都不应计入")
	}
}
