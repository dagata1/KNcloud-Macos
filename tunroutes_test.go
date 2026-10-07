package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRouteOps 记录每一次路由操作；failAdd/failDel 按路由描述注入失败。
type fakeRouteOps struct {
	log     *[]string
	table   map[routeKey]bool
	failAdd map[string]bool
	failDel map[string]bool
}

func newFakeOps(log *[]string) *fakeRouteOps {
	return &fakeRouteOps{log: log, table: map[routeKey]bool{}, failAdd: map[string]bool{}, failDel: map[string]bool{}}
}

func rdesc(r routeEntry) string { return fmt.Sprintf("%s/%d", u32ToIP(r.Dest), r.Bits) }

func (f *fakeRouteOps) AddRoute(r routeEntry) error {
	if f.failAdd[rdesc(r)] {
		*f.log = append(*f.log, "add-fail "+rdesc(r))
		return errors.New("injected add failure")
	}
	*f.log = append(*f.log, "add "+rdesc(r))
	if f.table[r.routeKey] {
		return errRouteExists
	}
	f.table[r.routeKey] = true
	return nil
}

func (f *fakeRouteOps) DeleteRoute(r routeEntry) error {
	if f.failDel[rdesc(r)] {
		*f.log = append(*f.log, "del-fail "+rdesc(r))
		return errors.New("injected delete failure")
	}
	*f.log = append(*f.log, "del "+rdesc(r))
	if !f.table[r.routeKey] {
		return errRouteNotFound
	}
	delete(f.table, r.routeKey)
	return nil
}

var (
	testTunIdx = uint32(42)
	testPhys   = physHop{IfIndex: 7, NextHop: ipToU32(net.ParseIP("192.168.1.1"))}
)

func testPlan(t *testing.T, policy string, nodeIPs ...string) []routeEntry {
	t.Helper()
	var hops []hopRoute
	for _, s := range nodeIPs {
		hops = append(hops, hopRoute{IP: net.ParseIP(s), Hop: testPhys})
	}
	plan, _, err := buildTunRoutePlan(tunRoutePlanInput{
		Policy:     policy,
		TunIdx:     testTunIdx,
		TunGateway: ipToU32(net.ParseIP(tunGateway)),
		HijackDNS:  true,
		NodeHops:   hops,
		DNSHops:    []hopRoute{{IP: net.ParseIP("223.5.5.5"), Hop: testPhys}},
		Phys:       testPhys,
	})
	if err != nil {
		t.Fatalf("plan %s: %v", policy, err)
	}
	return plan
}

func indexOf(plan []routeEntry, desc string, ifIdx uint32) int {
	for i, r := range plan {
		if rdesc(r) == desc && r.IfIndex == ifIdx {
			return i
		}
	}
	return -1
}

func TestTunRoutePlanShapes(t *testing.T) {
	g := testPlan(t, "global", "54.178.104.134")
	b := testPlan(t, "bypass-cn", "54.178.104.134")
	if n := countKind(g, "bypass"); n != len(privateBypassCIDRs) {
		t.Fatalf("global: %d bypass routes, want only the %d private ranges", n, len(privateBypassCIDRs))
	}
	if n := countKind(b, "bypass"); n < 3000 {
		t.Fatalf("bypass-cn: only %d bypass routes, want thousands of CN CIDRs", n)
	}
	for _, plan := range [][]routeEntry{g, b} {
		node := indexOf(plan, "54.178.104.134/32", testPhys.IfIndex)
		def1 := indexOf(plan, "0.0.0.0/1", testTunIdx)
		def2 := indexOf(plan, "128.0.0.0/1", testTunIdx)
		dns := indexOf(plan, tunDnsAddr+"/32", testTunIdx)
		if node < 0 || def1 < 0 || def2 < 0 || dns < 0 {
			t.Fatalf("missing core routes: node=%d def=%d/%d dns=%d", node, def1, def2, dns)
		}
		if node > def1 || node > def2 {
			t.Fatalf("node /32 must be installed before default routes (node=%d def=%d/%d)", node, def1, def2)
		}
		// 绕过网段在默认路由之前写入：任何时刻国内地址都不会先被吸进 TUN
		for i, r := range plan {
			if r.Kind == "bypass" && (i > def1 || r.IfIndex != testPhys.IfIndex || r.NextHop != testPhys.NextHop) {
				t.Fatalf("bypass route %s misplaced (index %d, def at %d)", r, i, def1)
			}
		}
	}
	// 223.5.5.5（阿里 DNS，国内地址）在绕过大陆下走物理网卡
	if indexOf(b, "223.5.5.5/32", testPhys.IfIndex) < 0 {
		t.Fatal("DNS server /32 missing")
	}
	if _, err := tunPolicyShapeFor("direct"); err == nil {
		t.Fatal("direct must not be a TUN policy")
	}
	p := testPlan(t, "proxy-cn", "54.178.104.134")
	if indexOf(p, "0.0.0.0/1", testTunIdx) >= 0 {
		t.Fatal("proxy-cn must not install default routes")
	}
}

func countKind(plan []routeEntry, kind string) int {
	n := 0
	for _, r := range plan {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

func TestTunRoutePlanSstapRules(t *testing.T) {
	dir := t.TempDir()
	skip := filepath.Join(dir, "skip.rules")
	only := filepath.Join(dir, "only.rules")
	os.WriteFile(skip, []byte("#Skip test,desc,1,0,1,0,1,0,By-KNcloud\r\n1.0.1.0/24\r\n1.0.2.0/23\r\n8.8.8.0/24\r\n"), 0644)
	os.WriteFile(only, []byte("#Only test,desc,0,0,1,0,1,0,By-KNcloud\n9.9.9.0/24\n"), 0644)
	s := testPlan(t, "sstap:"+skip, "54.178.104.134")
	if indexOf(s, "1.0.0.0/22", testPhys.IfIndex) < 0 && indexOf(s, "1.0.1.0/24", testPhys.IfIndex) < 0 {
		t.Fatalf("skip rule CIDRs must go via physical NIC: %v", s)
	}
	if indexOf(s, "8.8.8.0/24", testPhys.IfIndex) < 0 || indexOf(s, "0.0.0.0/1", testTunIdx) < 0 {
		t.Fatal("skip rule: want listed CIDRs bypassed and default routes into TUN")
	}
	o := testPlan(t, "sstap:"+only, "54.178.104.134")
	if indexOf(o, "9.9.9.0/24", testTunIdx) < 0 || indexOf(o, "0.0.0.0/1", testTunIdx) >= 0 {
		t.Fatal("proxy-only rule: want only listed CIDRs into TUN")
	}
	if _, _, err := buildTunRoutePlan(tunRoutePlanInput{Policy: "sstap:" + filepath.Join(dir, "missing.rules"), TunIdx: 1}); err == nil {
		t.Fatal("missing rule file must be an error")
	}
}

func TestAggregateCIDRs(t *testing.T) {
	in := parseCIDRList("10.0.0.0/24\n10.0.1.0/24\n10.0.0.128/25\n10.0.3.0/24")
	got := aggregateCIDRs(in)
	var s []string
	for _, c := range got {
		s = append(s, c.String())
	}
	if strings.Join(s, ",") != "10.0.0.0/23,10.0.3.0/24" {
		t.Fatalf("aggregate = %v", s)
	}
	raw := parseCIDRList(cnRoutesTxt)
	if agg := cnCIDRs(); len(agg) == 0 || len(agg) > len(raw) {
		t.Fatalf("cn aggregate %d vs raw %d", len(agg), len(raw))
	}
}

// 换模式：只增删绕过网段，默认路由/节点 /32/DNS 劫持一条都不碰；先加后删。
func TestTunRouteSyncModeSwitch(t *testing.T) {
	var log []string
	ops := newFakeOps(&log)
	st := newTunRouteState()
	g := testPlan(t, "global", "54.178.104.134")
	if _, _, err := st.sync(ops, g); err != nil {
		t.Fatal(err)
	}
	log = nil
	b := testPlan(t, "bypass-cn", "54.178.104.134")
	added, removed, err := st.sync(ops, b)
	if err != nil || removed != 0 || added != countKind(b, "bypass")-len(privateBypassCIDRs) {
		t.Fatalf("global→bypass: +%d -%d err=%v", added, removed, err)
	}
	for _, l := range log {
		if !strings.HasPrefix(l, "add ") {
			t.Fatalf("global→bypass must only add, got %q", l)
		}
	}
	log = nil
	added, removed, err = st.sync(ops, g)
	if err != nil || added != 0 || removed != countKind(b, "bypass")-len(privateBypassCIDRs) {
		t.Fatalf("bypass→global: +%d -%d err=%v", added, removed, err)
	}
	for _, l := range log {
		if strings.HasSuffix(l, "/1") || strings.Contains(l, "54.178.104.134") || strings.Contains(l, tunDnsAddr) {
			t.Fatalf("mode switch touched a core route: %q", l)
		}
	}
	if len(ops.table) != len(g) || st.count("") != len(g) {
		t.Fatalf("table %d / book %d, want %d", len(ops.table), st.count(""), len(g))
	}
}

// 换节点顺序：加新 /32 → 换出站 → 删旧 /32 → 重启转发 → 清 DNS；分流路由不动。
func TestTunNodeSwitchOrdering(t *testing.T) {
	var log []string
	ops := newFakeOps(&log)
	st := newTunRouteState()
	if _, _, err := st.sync(ops, testPlan(t, "bypass-cn", "54.178.104.134")); err != nil {
		t.Fatal(err)
	}
	log = nil
	deps := tunSwitchDeps{
		commitOutbound:    func() error { log = append(log, "commit"); return nil },
		restartForwarding: func() error { log = append(log, "restart"); return nil },
		flushDNS:          func() { log = append(log, "flush") },
	}
	if err := runTunNodeSwitch(st, ops, testPlan(t, "bypass-cn", "47.128.251.122"), deps); err != nil {
		t.Fatal(err)
	}
	want := []string{"add 47.128.251.122/32", "commit", "del 54.178.104.134/32", "restart", "flush"}
	if strings.Join(log, "|") != strings.Join(want, "|") {
		t.Fatalf("switch order:\n got %v\nwant %v", log, want)
	}
	if st.has(newRoute(net.IPNet{IP: net.ParseIP("54.178.104.134").To4(), Mask: net.CIDRMask(32, 32)}, testPhys.NextHop, testPhys.IfIndex, 0, "").routeKey) {
		t.Fatal("old node /32 still booked")
	}
	if n := st.count("host"); n != 2 { // 新节点 + DNS 服务器
		t.Fatalf("host routes after switch = %d, want 2", n)
	}
}

// 新节点 /32 写不进：拒绝且不换出站、不重启转发，账与系统都恢复原样。
func TestTunNodeSwitchRejectedOnRouteFailure(t *testing.T) {
	var log []string
	ops := newFakeOps(&log)
	st := newTunRouteState()
	old := testPlan(t, "global", "54.178.104.134")
	st.sync(ops, old)
	ops.failAdd["47.128.251.122/32"] = true
	called := false
	deps := tunSwitchDeps{
		commitOutbound:    func() error { called = true; return nil },
		restartForwarding: func() error { called = true; return nil },
		flushDNS:          func() { called = true },
	}
	err := runTunNodeSwitch(st, ops, testPlan(t, "global", "47.128.251.122", "47.128.251.123"), deps)
	if !errors.Is(err, errNodeRejected) || called {
		t.Fatalf("err=%v called=%v, want errNodeRejected and no further steps", err, called)
	}
	if st.count("") != len(old) || len(ops.table) != len(old) {
		t.Fatalf("book %d table %d, want original %d (partial add must be undone)", st.count(""), len(ops.table), len(old))
	}
}

// 出站被拒（旧出站已放回）：新 /32 撤回，返回 errNodeRejected。
func TestTunNodeSwitchRejectedOnOutbound(t *testing.T) {
	var log []string
	ops := newFakeOps(&log)
	st := newTunRouteState()
	old := testPlan(t, "global", "54.178.104.134")
	st.sync(ops, old)
	restarted := false
	deps := tunSwitchDeps{
		commitOutbound:    func() error { return fmt.Errorf("%w: bad outbound", errNodeRejected) },
		restartForwarding: func() error { restarted = true; return nil },
		flushDNS:          func() {},
	}
	err := runTunNodeSwitch(st, ops, testPlan(t, "global", "47.128.251.122"), deps)
	if !errors.Is(err, errNodeRejected) || restarted {
		t.Fatalf("err=%v restarted=%v", err, restarted)
	}
	if len(ops.table) != len(old) || !ops.table[old[0].routeKey] {
		t.Fatal("routes not restored after outbound rejection")
	}
}

// 失败路径记账：加成功的都入账；软停按账全删；删不掉的留账，下次重试。
func TestTunRouteFailureBookkeeping(t *testing.T) {
	var log []string
	ops := newFakeOps(&log)
	st := newTunRouteState()
	plan := testPlan(t, "global", "54.178.104.134")
	ops.failAdd["128.0.0.0/1"] = true
	_, _, err := st.sync(ops, plan)
	if err == nil {
		t.Fatal("want error")
	}
	if st.count("") != len(plan)-1 || !ops.table[plan[indexOf(plan, "0.0.0.0/1", testTunIdx)].routeKey] {
		t.Fatalf("booked %d of %d; successful routes (incl. 0/1) must stay booked", st.count(""), len(plan))
	}
	ops.failDel[tunDnsAddr+"/32"] = true
	removed, failed := st.clear(ops)
	if failed != 1 || removed != len(plan)-2 || st.count("") != 1 {
		t.Fatalf("clear removed=%d failed=%d left=%d", removed, failed, st.count(""))
	}
	delete(ops.failDel, tunDnsAddr+"/32")
	if _, failed := st.clear(ops); failed != 0 || len(ops.table) != 0 {
		t.Fatalf("retry clear failed=%d table=%d", failed, len(ops.table))
	}
}

// 「已存在」视为成功并入账；删除时「不存在」视为已删。
func TestTunRouteExistsAndNotFound(t *testing.T) {
	var log []string
	ops := newFakeOps(&log)
	plan := testPlan(t, "global", "54.178.104.134")
	ops.table[plan[0].routeKey] = true // 上次残留
	st := newTunRouteState()
	if _, _, err := st.sync(ops, plan); err != nil {
		t.Fatal(err)
	}
	delete(ops.table, plan[1].routeKey) // 被外部删掉
	if _, failed := st.clear(ops); failed != 0 || st.count("") != 0 {
		t.Fatalf("failed=%d left=%d", failed, st.count(""))
	}
}

func TestTunCoreProfile(t *testing.T) {
	a := &App{
		routingMode: "bypass-cn",
		settings:    AppSettings{SocksPort: 10808, HttpPort: 10809, MuxEnabled: true, DnsServers: "1.1.1.1"},
	}
	vless := NodeItem{ID: "v", Protocol: "VLESS", Address: "example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Network: "tcp", Security: "tls"}
	vision := vless
	vision.Flow = "xtls-rprx-vision"

	cfg, err := a.buildCoreConfigJSON(vless)
	if err != nil || !strings.Contains(cfg, `"mux"`) || strings.Contains(cfg, `"sockopt"`) {
		t.Fatalf("proxy mode: want mux and no sockopt: %v %s", err, cfg)
	}
	if cfg, _ := a.buildCoreConfigJSON(vision); strings.Contains(cfg, `"mux"`) {
		t.Fatal("Vision flow must never use mux")
	}
	a.tunEgressIface = "以太网"
	cfg, err = a.buildCoreConfigJSON(vless)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, `"mux"`) {
		t.Fatal("TUN mode must disable mux")
	}
	if strings.Count(cfg, `"interface":"以太网"`) != 2 {
		t.Fatalf("TUN mode: proxy and direct outbounds must bind the physical NIC: %s", cfg)
	}
	if !strings.Contains(cfg, `"destOverride":["http","tls"]`) {
		t.Fatalf("TUN mode: socks-in sniffing must be http/tls only: %s", cfg)
	}
	if strings.Contains(cfg, tunUDPInboundTag) {
		t.Fatal("no UDP inbound without a port")
	}
	a.tunUDPPort = 23456
	cfg, err = a.buildCoreConfigJSON(vless)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, in := range parsed.Inbounds {
		if in["tag"] == tunUDPInboundTag {
			found = true
			if in["sniffing"] != nil || in["port"] != float64(23456) || in["listen"] != "127.0.0.1" {
				t.Fatalf("TUN UDP inbound must be loopback, unsniffed (Xray QUIC sniffer panics): %v", in)
			}
		}
	}
	if !found {
		t.Fatalf("TUN mode: missing %s inbound: %s", tunUDPInboundTag, cfg)
	}
	t.Setenv("APPDATA", t.TempDir())
	dir, err := ensureGeoAssets()
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("xray.location.asset", dir)
	if _, err := a.buildCoreConfigLocked(vless); err != nil {
		t.Fatalf("TUN profile config must build in Xray: %v", err)
	}
}

func TestSaveSettingsRejectedWhileTun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	a := &App{tunRunning: true, settings: AppSettings{SocksPort: 10808, HttpPort: 10809, DnsServers: "1.1.1.1", Theme: "dark", UiMode: "classic"}}
	n := a.settings
	n.SocksPort = 20808
	if err := a.SaveSettings(n); err == nil || a.settings.SocksPort != 10808 {
		t.Fatalf("socks port change while TUN: err=%v port=%d", err, a.settings.SocksPort)
	}
	n = a.settings
	n.DnsServers = "8.8.8.8"
	if err := a.SaveSettings(n); err == nil || a.settings.DnsServers != "1.1.1.1" {
		t.Fatalf("dns change while TUN: err=%v dns=%s", err, a.settings.DnsServers)
	}
}

func TestPersistedRoutingModeKeepsUserChoice(t *testing.T) {
	a := &App{routingMode: "global", prevRoutingMode: "direct"}
	if m := a.persistedRoutingMode(); m != "direct" {
		t.Fatalf("persisted %s, want direct", m)
	}
}
