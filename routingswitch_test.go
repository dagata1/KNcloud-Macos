package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法绑定本地端口，跳过: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newRoutingTestApp 用真实的 buildCoreConfigJSON（含 geoip/geosite 规则）起一个主内核。
// 节点指向本机不可达端口：测试只看路由决策与连接清扫，不需要节点真的可用。
func newRoutingTestApp(t *testing.T, mode string) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	a := &App{
		routingMode: mode,
		settings: AppSettings{
			SocksPort: freePort(t), HttpPort: freePort(t),
			DnsServers: "1.1.1.1", MuxEnabled: false,
		},
		nodes: []NodeItem{
			{ID: "n1", Name: "节点一", Protocol: "Shadowsocks", Address: "127.0.0.1", Port: 1, Method: "aes-128-gcm", UUID: "pw1", Network: "tcp", Active: true},
			{ID: "n2", Name: "节点二", Protocol: "Shadowsocks", Address: "127.0.0.1", Port: 2, Method: "aes-128-gcm", UUID: "pw2", Network: "tcp"},
		},
		activeNodeID: "n1",
	}
	a.mu.Lock()
	err := a.startCoreLocked()
	if err == nil {
		a.coreRunning = true
	}
	a.mu.Unlock()
	if err != nil {
		t.Fatalf("start core: %v", err)
	}
	t.Cleanup(func() {
		a.mu.Lock()
		a.stopCoreLocked()
		a.coreRunning = false
		a.mu.Unlock()
	})
	time.Sleep(100 * time.Millisecond)
	return a
}

// routeOf 让主内核的路由器为目标做一次决策，返回出站 tag。
func routeOf(t *testing.T, inst *xcore.Instance, dest xnet.Destination) string {
	t.Helper()
	sr := swappableRouterOf(inst)
	if sr == nil {
		t.Fatal("主内核应使用可热替换的 router")
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	r, err := sr.PickRoute(routing_session.AsRoutingContext(ctx))
	if err != nil {
		t.Fatalf("PickRoute(%v): %v", dest, err)
	}
	return r.GetOutboundTag()
}

var (
	destForeignIP     = xnet.TCPDestination(xnet.ParseAddress("8.8.8.8"), 443)
	destMainlandIP    = xnet.TCPDestination(xnet.ParseAddress("114.114.114.114"), 443)
	destForeignDomain = xnet.TCPDestination(xnet.DomainAddress("www.google.com"), 443)
	destCNDomain      = xnet.TCPDestination(xnet.DomainAddress("www.baidu.com"), 443)
)

// wantRoutes 每种策略下四类目标应走的出站：境外 IP、境内 IP、境外域名、境内域名。
var wantRoutes = map[string][4]string{
	"global":    {"proxy", "proxy", "proxy", "proxy"},
	"direct":    {"direct", "direct", "direct", "direct"},
	"bypass-cn": {"proxy", "direct", "proxy", "direct"},
}

func checkRoutes(t *testing.T, a *App, mode string) {
	t.Helper()
	a.mu.RLock()
	inst := a.xrayInst
	a.mu.RUnlock()
	want := wantRoutes[mode]
	got := [4]string{
		routeOf(t, inst, destForeignIP), routeOf(t, inst, destMainlandIP),
		routeOf(t, inst, destForeignDomain), routeOf(t, inst, destCNDomain),
	}
	if got != want {
		t.Fatalf("mode %s: routes (foreignIP, cnIP, foreignDomain, cnDomain) = %v, want %v", mode, got, want)
	}
}

// TestSetRoutingModeAppliesLiveWithoutRestart 内核运行中切换策略：路由立即按新策略决策，
// 且是就地替换（同一实例、入站不断），六种方向的切换都覆盖。
func TestSetRoutingModeAppliesLiveWithoutRestart(t *testing.T) {
	a := newRoutingTestApp(t, "global")
	a.mu.RLock()
	inst := a.xrayInst
	a.mu.RUnlock()
	checkRoutes(t, a, "global")

	prev := "global"
	for _, m := range []string{"direct", "bypass-cn", "global", "bypass-cn", "direct", "global"} {
		ok, err := a.SetRoutingMode(m)
		if !ok || err != nil {
			t.Fatalf("SetRoutingMode %s -> %s: ok=%v err=%v", prev, m, ok, err)
		}
		a.mu.RLock()
		same, running, cur := a.xrayInst == inst, a.coreRunning, a.routingMode
		a.mu.RUnlock()
		if !same || !running {
			t.Fatalf("%s -> %s: 应就地切换（同一实例、内核在跑），same=%v running=%v", prev, m, same, running)
		}
		if cur != m || a.GetCoreStatus().RoutingMode != m {
			t.Fatalf("%s -> %s: 状态中的策略为 %s", prev, m, cur)
		}
		checkRoutes(t, a, m)
		prev = m
	}
}

// TestSetRoutingModeKeepsExistingConnections 换策略后，已建立的（keep-alive）隧道保持原出口
// 不被切断（#13，与 v2rayN 一致），入站监听保持可用，新隧道正常。
func TestSetRoutingModeKeepsExistingConnections(t *testing.T) {
	echo := startEchoServer(t)
	a := newRoutingTestApp(t, "global")
	a.mu.RLock()
	inst, port := a.xrayInst, a.settings.SocksPort
	a.mu.RUnlock()

	// 127.0.0.1 属于 geoip:private，任何策略下都走 direct 出站。
	c := socksDial(t, port, echo)
	defer c.Close()
	if err := echoOnce(c, "before"); err != nil {
		t.Fatalf("切换前隧道应可用: %v", err)
	}
	if !waitFor(func() bool { return outboundConnTracker.countTag(inst, "direct") == 1 }, 2*time.Second) {
		t.Fatalf("direct 出站连接应被记账，实际 %d", outboundConnTracker.countTag(inst, "direct"))
	}
	if _, err := a.SetRoutingMode("direct"); err != nil {
		t.Fatal(err)
	}
	if waitClosed(c, 1500*time.Millisecond) {
		t.Fatal("换策略不应切断已建立的连接")
	}
	c.SetReadDeadline(time.Time{})
	if err := echoOnce(c, "still-alive"); err != nil {
		t.Fatalf("换策略后存量隧道应继续可用: %v", err)
	}
	c2 := socksDial(t, port, echo)
	defer c2.Close()
	if err := echoOnce(c2, "after"); err != nil {
		t.Fatalf("换策略后新隧道应可用: %v", err)
	}
}

// TestRoutingModePersistsAndSurvivesSelectNode 策略落盘；换节点后策略不变且仍生效。
func TestRoutingModePersistsAndSurvivesSelectNode(t *testing.T) {
	a := newRoutingTestApp(t, "global")
	if _, err := a.SetRoutingMode("bypass-cn"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SelectNode("n2"); err != nil {
		t.Fatalf("SelectNode: %v", err)
	}
	if m := a.GetCoreStatus().RoutingMode; m != "bypass-cn" {
		t.Fatalf("换节点后策略 = %s，应保持 bypass-cn", m)
	}
	checkRoutes(t, a, "bypass-cn")

	dir, err := appConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"routingMode": "bypass-cn"`) && !strings.Contains(string(b), `"routingMode":"bypass-cn"`) {
		t.Fatalf("config.json 未保存 routingMode=bypass-cn")
	}
	r := &App{}
	r.loadPersisted()
	if r.routingMode != "bypass-cn" {
		t.Fatalf("重新加载后的策略 = %q", r.routingMode)
	}
}

// TestSwappableRouterReloadFailureKeepsRules 新规则构建失败时保持原规则。
func TestSwappableRouterReloadFailureKeepsRules(t *testing.T) {
	a := newRoutingTestApp(t, "bypass-cn")
	a.mu.RLock()
	inst := a.xrayInst
	a.mu.RUnlock()
	bad := &router.Config{Rule: []*router.RoutingRule{{
		TargetTag: &router.RoutingRule_BalancingTag{BalancingTag: "no-such-balancer"},
		Networks:  []xnet.Network{xnet.Network_TCP},
	}}}
	if err := swappableRouterOf(inst).Reload(bad); err == nil {
		t.Fatal("引用不存在的 balancer 应构建失败")
	}
	checkRoutes(t, a, "bypass-cn")
}

// TestStopCoreClosesLeftoverConnections 停内核（也是整体重启的第一步）时，
// 挂在旧实例上的隧道必须一并切断，不能继续按旧配置转发。
func TestStopCoreClosesLeftoverConnections(t *testing.T) {
	echo := startEchoServer(t)
	a := newRoutingTestApp(t, "global")
	a.mu.RLock()
	port := a.settings.SocksPort
	a.mu.RUnlock()
	c := socksDial(t, port, echo)
	defer c.Close()
	if err := echoOnce(c, "x"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.stopCoreLocked()
	a.coreRunning = false
	a.mu.Unlock()
	if !waitClosed(c, 3*time.Second) {
		t.Fatal("停内核后旧实例上的连接应被关闭")
	}
}
