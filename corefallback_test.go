package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestLooksLikePortInUse(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&portInUseError{name: "HTTP", port: 10809}, true},
		{fmt.Errorf("start: %w", &portInUseError{name: "SOCKS5", port: 1}), true},
		{fmt.Errorf("%w (x)", errPortInUse), true},
		{errors.New("listen tcp 127.0.0.1:10809: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted."), true},
		{errors.New("listen tcp 127.0.0.1:1: bind: An attempt was made to access a socket in a way forbidden by its access permissions."), true},
		{errors.New("failed to build core config: unknown cipher"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := looksLikePortInUse(c.err); got != c.want {
			t.Errorf("looksLikePortInUse(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func withFastBackoff(t *testing.T) {
	old := coreRetryBackoff
	coreRetryBackoff = []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
	t.Cleanup(func() { coreRetryBackoff = old })
}

// freePorts 取 n 个当前空闲的回环端口。
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	var out []int
	var ls []net.Listener
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("cannot listen: %v", err)
		}
		ls = append(ls, l)
		out = append(out, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range ls {
		l.Close()
	}
	return out
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	useTempConfigDir(t)
	p := freePorts(t, 2)
	a := &App{routingMode: "bypass-cn"}
	a.settings.SocksPort, a.settings.HttpPort = p[0], p[1]
	t.Cleanup(func() {
		a.coreRetryGen.Add(1)
		a.cleaned.Store(true)
		a.mu.Lock()
		a.stopCoreLocked()
		a.mu.Unlock()
	})
	return a
}

func canDial(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// 没有节点（首次登录前）：内核以直连配置启动，本地 SOCKS / HTTP 照样监听。
func TestStartCoreWithoutNodeRunsDirectOnly(t *testing.T) {
	a := newTestApp(t)
	a.mu.Lock()
	err := a.startCoreLocked()
	a.mu.Unlock()
	if err != nil {
		t.Fatalf("no node must still start the core (direct only): %v", err)
	}
	if a.xrayInst == nil || a.coreNodeID != "" {
		t.Fatalf("want a direct-only instance, inst=%v coreNodeID=%q", a.xrayInst, a.coreNodeID)
	}
	if !canDial(a.settings.SocksPort) || !canDial(a.settings.HttpPort) {
		t.Fatal("local SOCKS/HTTP inbounds must be listening")
	}
	if int(a.liveHTTPPort.Load()) != a.settings.HttpPort {
		t.Fatalf("liveHTTPPort=%d, want %d", a.liveHTTPPort.Load(), a.settings.HttpPort)
	}
}

// 直连配置：没有 proxy 出站，规则全部指向 direct（不管保存的策略是什么）。
func TestDirectCoreConfigHasNoProxy(t *testing.T) {
	a := &App{routingMode: "global"}
	a.settings.SocksPort, a.settings.HttpPort = 10808, 10809
	raw, err := a.buildDirectCoreConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds  []map[string]interface{} `json:"inbounds"`
		Outbounds []map[string]interface{} `json:"outbounds"`
		Routing   struct {
			Rules []map[string]interface{} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) < 2 {
		t.Fatalf("SOCKS/HTTP inbounds missing: %v", cfg.Inbounds)
	}
	for _, o := range cfg.Outbounds {
		if o["tag"] == proxyOutboundTag {
			t.Fatal("direct-only config must not have a proxy outbound")
		}
	}
	if cfg.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("default outbound must be direct, got %v", cfg.Outbounds[0]["tag"])
	}
	for _, r := range cfg.Routing.Rules {
		if r["outboundTag"] != "direct" {
			t.Fatalf("rule %v does not go direct", r)
		}
	}
	if _, err := decodeCoreConfig(raw); err != nil {
		t.Fatalf("direct-only config does not build: %v", err)
	}
}

// 端口被别的程序占用：自动换到空闲端口、写回设置，内核照常起来。
func TestStartCoreMovesBusyPorts(t *testing.T) {
	a := newTestApp(t)
	holdS, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.settings.SocksPort))
	if err != nil {
		t.Skip(err)
	}
	defer holdS.Close()
	holdH, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort))
	if err != nil {
		t.Skip(err)
	}
	defer holdH.Close()
	oldS, oldH := a.settings.SocksPort, a.settings.HttpPort

	a.mu.Lock()
	err = a.startCoreLocked()
	a.mu.Unlock()
	if err != nil {
		t.Fatalf("busy ports must be replaced automatically: %v", err)
	}
	if a.settings.SocksPort == oldS || a.settings.HttpPort == oldH || a.settings.SocksPort == a.settings.HttpPort {
		t.Fatalf("ports not moved: socks %d->%d http %d->%d", oldS, a.settings.SocksPort, oldH, a.settings.HttpPort)
	}
	if !canDial(a.settings.SocksPort) || !canDial(a.settings.HttpPort) {
		t.Fatal("core is not listening on the new ports")
	}
	if got := a.GetSettings(); got.SocksPort != a.settings.SocksPort || got.HttpPort != a.settings.HttpPort {
		t.Fatalf("settings shown to the UI not updated: %+v", got)
	}
	st := a.GetCoreStatus()
	if st.SocksPort != a.settings.SocksPort || st.HttpPort != a.settings.HttpPort {
		t.Fatalf("status ports not updated: %+v", st)
	}
}

// 节点配置起不来（Xray 不支持的协议）：内核立即降级为直连配置继续运行，
// 自动重试用完后保持直连运行（fallback），不会停在「内核没开」。
func TestNodeFailureFallsBackToDirect(t *testing.T) {
	withFastBackoff(t)
	a := newTestApp(t)
	a.nodes = []NodeItem{{ID: "hy2", Name: "hy2", Protocol: "Hysteria2", Address: "127.0.0.1", Port: 24433, Active: true}}
	a.activeNodeID = "hy2"

	if _, err := a.RestartCore(); err == nil {
		t.Fatal("want an error for an unsupported node")
	}
	if !a.mu.TryLock() {
		t.Fatal("RestartCore left a.mu locked")
	}
	running, fallback := a.coreRunning, a.coreFallback
	a.mu.Unlock()
	if !running || !fallback {
		t.Fatalf("core must keep running direct-only: running=%v fallback=%v", running, fallback)
	}
	if !canDial(a.settings.HttpPort) {
		t.Fatal("HTTP inbound must stay available in fallback")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		st := a.GetCoreStatus()
		if st.CoreState == "fallback" && !a.isRetrying() {
			if st.CoreError == "" || !st.Running || !st.CoreDirectOnly {
				t.Fatalf("fallback status incomplete: %+v", st)
			}
			break
		}
		if st.CoreState != "fallback" {
			t.Fatalf("core left fallback state: %+v", st)
		}
		if time.Now().After(deadline) {
			t.Fatal("retry loop did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !canDial(a.settings.HttpPort) {
		t.Fatal("core stopped after retries")
	}
}

func (a *App) isRetrying() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.coreRetrying
}

// 节点恢复（换成可用节点）后，直连兜底切回正常配置。
func TestSelectNodeLeavesFallback(t *testing.T) {
	withFastBackoff(t)
	a := newTestApp(t)
	a.nodes = []NodeItem{
		{ID: "hy2", Name: "hy2", Protocol: "Hysteria2", Address: "127.0.0.1", Port: 24433, Active: true},
		{ID: "ok", Name: "ok", Protocol: "SOCKS", Address: "127.0.0.1", Port: 1},
	}
	a.activeNodeID = "hy2"
	a.RestartCore()
	if _, err := a.SelectNode("ok"); err != nil {
		t.Fatalf("SelectNode: %v", err)
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.coreRunning || a.coreFallback || a.coreNodeID != "ok" {
		t.Fatalf("want normal config on node ok: running=%v fallback=%v node=%q", a.coreRunning, a.coreFallback, a.coreNodeID)
	}
}

// 取消（换节点 / 手动操作 / 退出）后，正在等待的重试不再执行。
func TestCoreRetryLoopCanceled(t *testing.T) {
	old := coreRetryBackoff
	coreRetryBackoff = []time.Duration{300 * time.Millisecond, 300 * time.Millisecond, 300 * time.Millisecond}
	t.Cleanup(func() { coreRetryBackoff = old })
	a := &App{}
	a.mu.Lock()
	a.coreRetrying = true
	a.mu.Unlock()
	gen := a.coreRetryGen.Add(1)
	done := make(chan struct{})
	go func() { a.coreRetryLoop(gen); close(done) }()
	time.Sleep(50 * time.Millisecond)
	a.coreRetryGen.Add(1) // 取消
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop ignored cancellation")
	}
	if a.coreErr != "" {
		t.Fatalf("canceled loop still attempted a start: %q", a.coreErr)
	}
}

// 「断开」（ToggleCore(false)）只撤系统代理 / TUN，内核继续运行。
func TestToggleCoreOffKeepsCoreRunning(t *testing.T) {
	a := newTestApp(t)
	if ok, err := a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("ToggleCore(true) = %v, %v", ok, err)
	}
	if ok, _ := a.ToggleCore(false); !ok {
		t.Fatal("ToggleCore(false) must leave the core running")
	}
	if !canDial(a.settings.SocksPort) {
		t.Fatal("core stopped")
	}
}
