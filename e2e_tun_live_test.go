//go:build e2elive

package main

// 实机 TUN 测试（需管理员 + 交互会话 DPAPI）：go test -tags e2elive -run TestLiveTun -v
// 只在测试机上跑；结果逐行以 "ROW |" 打印，便于汇总成表。

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func curlNoProxy(url string, extra ...string) (string, error) {
	args := append([]string{"--noproxy", "*", "-s", "-m", "8"}, extra...)
	args = append(args, url)
	out, err := exec.Command("curl.exe", args...).Output()
	return strings.TrimSpace(string(out)), err
}

func curlTiming(proxy, url string) string {
	args := []string{"-s", "-o", "NUL", "-m", "20", "-w", "dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} speed=%{speed_download}"}
	if proxy != "" {
		args = append(args, "-x", proxy)
	} else {
		args = append(args, "--noproxy", "*")
	}
	args = append(args, url)
	out, _ := exec.Command("curl.exe", args...).Output()
	return strings.TrimSpace(string(out))
}

func procStats() string {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("$p=Get-Process -Id %d; '{0} {1}' -f $p.HandleCount,$p.Threads.Count", os.Getpid())).Output()
	return strings.TrimSpace(string(out))
}

func routeCount4() int {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command", "(Get-NetRoute -AddressFamily IPv4).Count").Output()
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

func psOut(cmd string) string {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command", cmd).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func TestLiveTun(t *testing.T) {
	a, _ := setupLiveApp(t)
	var jp, sg NodeItem
	for _, n := range a.GetNodes() {
		if strings.Contains(strings.ToUpper(n.Name), "V6") {
			continue
		}
		if jp.ID == "" && strings.Contains(n.Name, "日本") {
			jp = n
		}
		if sg.ID == "" && strings.Contains(n.Name, "新加坡") {
			sg = n
		}
	}
	if jp.ID == "" || sg.ID == "" {
		t.Fatal("need 日本 and 新加坡 nodes")
	}
	jpIP, sgIP := nodeExitIP["日本"], nodeExitIP["新加坡"]
	t.Logf("nodes: 日本=%s:%d (%s) 新加坡=%s:%d (%s)", jp.Address, jp.Port, jp.Protocol, sg.Address, sg.Port, sg.Protocol)
	a.mu.Lock()
	a.routingMode = "bypass-cn"
	a.mu.Unlock()
	if _, err := a.SelectNode(jp.ID); err != nil {
		t.Fatal(err)
	}
	baseRoutes := routeCount4()
	baseDNS := psOut("(Get-DnsClientServerAddress -InterfaceIndex 9 -AddressFamily IPv4).ServerAddresses -join ','")
	t.Logf("ROW | baseline | routes=%d dns(if9)=%s", baseRoutes, baseDNS)

	if ok, err := a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("core: %v", err)
	}
	defer a.ToggleCore(false)
	time.Sleep(time.Second)

	// ---------- 性能：系统代理模式基准 ----------
	const dl = "https://speed.cloudflare.com/__down?bytes=30000000"
	const small = "https://www.google.com/generate_204"
	for i := 0; i < 3 && os.Getenv("LIVE_SKIP_PERF") != "1"; i++ {
		t.Logf("ROW | perf proxy-mode | small | %s", curlTiming("http://127.0.0.1:21081", small))
	}
	if os.Getenv("LIVE_SKIP_PERF") != "1" {
		t.Logf("ROW | perf proxy-mode | download30MB | %s", curlTiming("http://127.0.0.1:21081", dl))
	}

	// ---------- 开 TUN ----------
	t0 := time.Now()
	on, err := a.SimpleConnect(true)
	t.Logf("ROW | T0 start TUN | %v | on=%v err=%v", time.Since(t0).Round(time.Millisecond), on, err)
	if !on || err != nil {
		dumpLogs(t, a)
		t.Fatalf("SimpleConnect: %v", err)
	}
	defer func() {
		t1 := time.Now()
		a.SimpleConnect(false)
		time.Sleep(500 * time.Millisecond)
		rc := routeCount4()
		dns := psOut("(Get-DnsClientServerAddress -InterfaceIndex 9 -AddressFamily IPv4).ServerAddresses -join ','")
		tap := psOut("(Get-NetRoute -InterfaceAlias KNcloud-TAP -ErrorAction SilentlyContinue | Measure-Object).Count")
		marked := psOut("(Get-NetRoute -AddressFamily IPv4 | ? { $_.RouteMetric -eq 37 -or $_.RouteMetric -eq 4037 } | Measure-Object).Count")
		t.Logf("ROW | T8 stop TUN | %v | routes=%d (baseline %d) dns(if9)=%s (baseline %s) tapRoutes=%s markedBypass=%s mode=%s",
			time.Since(t1).Round(time.Millisecond), rc, baseRoutes, dns, baseDNS, tap, marked, a.GetCoreStatus().RoutingMode)
		if rc > baseRoutes+2 || dns != baseDNS || marked != "0" {
			t.Errorf("not restored to baseline")
		}
		dumpLogs(t, a)
	}()
	a.mu.RLock()
	t.Logf("ROW | routes installed | host=%d bypass=%d split=%d | egress=%s", a.tunRt.count("host"), a.tunRt.count("bypass"), a.tunRt.count("split"), a.tunEgressIface)
	a.mu.RUnlock()
	time.Sleep(time.Second)

	check := func(label, wantForeign, wantCN string) {
		f, _ := curlNoProxy("https://ifconfig.me/ip")
		c, _ := curlNoProxy("http://ip.3322.net")
		f, c = extractIP(f), extractIP(c)
		st := "OK"
		if f != wantForeign || c != wantCN {
			st = "FAIL"
			t.Errorf("%s: foreign=%s cn=%s want %s/%s", label, f, c, wantForeign, wantCN)
		}
		t.Logf("ROW | %s | ifconfig.me=%s ip.3322.net=%s | want %s / %s | %s", label, f, c, wantForeign, wantCN, st)
	}
	// T1 连通性 + 绕过大陆
	check("T1 bypass-cn 日本", jpIP, machineDirectIP)

	// T2 DNS：198.18.0.2 直接应答，无 ~1s 超时
	native := os.Getenv("KNCLOUD_NATIVE_TUN") == "1"
	for i := 0; i < 3 && !native; i++ {
		host := fmt.Sprintf("kn%d%d.example.com", time.Now().UnixNano()%100000, i)
		out := psOut(fmt.Sprintf("$t=Measure-Command { $r=Resolve-DnsName %s -Server %s -DnsOnly -ErrorAction SilentlyContinue }; '{0:N0}ms' -f $t.TotalMilliseconds", host, tunDnsAddr))
		real := psOut(fmt.Sprintf("$t=Measure-Command { $r=Resolve-DnsName www.%d.qq.com -DnsOnly -ErrorAction SilentlyContinue }; '{0:N0}ms' -f $t.TotalMilliseconds", time.Now().UnixNano()%100000))
		ans := psOut(fmt.Sprintf("(Resolve-DnsName www.baidu.com -Server %s -DnsOnly -Type A -ErrorAction SilentlyContinue | ? IPAddress | select -First 1).IPAddress", tunDnsAddr))
		t.Logf("ROW | T2 DNS | 198.18.0.2 random-name=%s | system resolver uncached=%s | baidu A via 198.18.0.2=%s", out, real, ans)
	}

	// 性能：TUN
	if os.Getenv("LIVE_SKIP_PERF") == "1" {
		goto modes
	}
	for i := 0; i < 3; i++ {
		t.Logf("ROW | perf tun bypass-cn | small | %s", curlTiming("", small))
	}
	t.Logf("ROW | perf tun bypass-cn | download30MB | %s", curlTiming("", dl))
	t.Logf("ROW | perf tun bypass-cn | CN download | %s", curlTiming("", "https://dldir1.qq.com/qqfile/qq/PCQQ9.7.17/QQ9.7.17.29225.exe"))
	t.Logf("ROW | perf proxy-mode | CN download | %s", curlTiming("http://127.0.0.1:21081", "https://dldir1.qq.com/qqfile/qq/PCQQ9.7.17/QQ9.7.17.29225.exe"))

	// T6 模式切换（TUN 不断）
modes:
	for _, m := range []string{"global", "bypass-cn", "global"} {
		t1 := time.Now()
		ok, err := a.SetRoutingMode(m)
		a.mu.RLock()
		nb := a.tunRt.count("bypass")
		a.mu.RUnlock()
		t.Logf("ROW | T6 SetRoutingMode %s | %v ok=%v err=%v bypassRoutes=%d tun=%v", m, time.Since(t1).Round(time.Millisecond), ok, err, nb, a.GetCoreStatus().TunRunning)
		time.Sleep(500 * time.Millisecond)
		if m == "global" {
			check("T6 global 日本", jpIP, jpIP)
		} else {
			check("T6 bypass-cn 日本", jpIP, machineDirectIP)
		}
	}
	if os.Getenv("LIVE_SKIP_PERF") != "1" {
		for i := 0; i < 2; i++ {
			t.Logf("ROW | perf tun global | small | %s", curlTiming("", small))
		}
		t.Logf("ROW | perf tun global | download30MB | %s", curlTiming("", dl))
	}

	// T3 换节点：200ms curl 循环 + 长连接；不得出现真实 IP；只剩新 /32
	ka := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 8 * time.Second}
	t.Logf("ROW | T3 keep-alive before | %s", getIP(ka, foreignEcho, false))
	var mu sync.Mutex
	var seen []string
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			out, _ := curlNoProxy("https://ifconfig.me/ip", "-m", "3")
			mu.Lock()
			seen = append(seen, extractIP(out))
			mu.Unlock()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	h0, _ := procStats(), 0
	t.Logf("ROW | T7 proc before switches | handles threads = %s", h0)
	order := []NodeItem{sg, jp, sg, jp, sg, jp, sg, jp, sg, jp}
	for i, n := range order {
		time.Sleep(1500 * time.Millisecond)
		t1 := time.Now()
		_, err := a.SelectNode(n.ID)
		d := time.Since(t1).Round(time.Millisecond)
		time.Sleep(700 * time.Millisecond)
		want := nodeExitIP[nodeKey(n.Name)]
		kaIP := getIP(ka, foreignEcho, false)
		a.mu.RLock()
		var hosts []string
		for _, r := range a.tunRt.entries("host") {
			hosts = append(hosts, u32ToIP(r.Dest).String())
		}
		a.mu.RUnlock()
		st := "OK"
		if err != nil || kaIP != want {
			st = "FAIL"
			t.Errorf("switch %d to %s: err=%v keepalive=%s want %s", i, n.Name, err, kaIP, want)
		}
		if i < 2 || i == len(order)-1 {
			t.Logf("ROW | T3 switch→%s | %v err=%v | keep-alive=%s want=%s | host /32s=%v | %s", n.Name, d, err, kaIP, want, hosts, st)
		}
	}
	close(stop)
	wg.Wait()
	leaks, fails := 0, 0
	for _, s := range seen {
		switch s {
		case machineDirectIP:
			leaks++
		case jpIP, sgIP:
		default:
			fails++
		}
	}
	t.Logf("ROW | T3 200ms loop | samples=%d realIPleaks=%d failed/timeouts=%d", len(seen), leaks, fails)
	if leaks > 0 {
		t.Errorf("real IP leaked %d times during node switches", leaks)
	}
	// 路由表里旧节点的 /32 是否残留（日本、新加坡同域名时只看解析到的 IP）
	t.Logf("ROW | T3 route table | %s", psOut("Get-NetRoute -AddressFamily IPv4 | ? { $_.DestinationPrefix -like '*/32' -and $_.RouteMetric -eq 1 } | % { $_.DestinationPrefix + ' if' + $_.ifIndex } | Out-String"))
	time.Sleep(3 * time.Second)
	t.Logf("ROW | T7 proc after 10 switches | handles threads = %s (before %s)", procStats(), h0)

	// T4 故障注入：不可解析的节点 → 拒绝，TUN 不拆
	bad := NodeItem{ID: "e2e-unresolvable", Name: "坏节点", Protocol: "Shadowsocks", Address: "no-such-host.invalid", Port: 8388, Method: "aes-128-gcm", UUID: "x", Network: "tcp"}
	a.mu.Lock()
	a.nodes = append(a.nodes, bad)
	a.mu.Unlock()
	_, err = a.SelectNode(bad.ID)
	active := ""
	for _, n := range a.GetNodes() {
		if n.Active {
			active = n.Name
		}
	}
	f, _ := curlNoProxy("https://ifconfig.me/ip")
	t.Logf("ROW | T4 unresolvable node | err=%v | tunRunning=%v active=%s | ifconfig.me=%s", err, a.GetCoreStatus().TunRunning, active, extractIP(f))
	if err == nil || !a.GetCoreStatus().TunRunning || extractIP(f) != jpIP {
		t.Errorf("fault injection: TUN must stay up on the previous node")
	}

	// T5 SaveSettings 端口改动被拒
	s := a.GetSettings()
	s.SocksPort = 21090
	t.Logf("ROW | T5 SaveSettings(SocksPort) while TUN | err=%v", a.SaveSettings(s))

	// 回环观测：Xray 到节点的连接都走物理网卡
	t.Logf("ROW | loop check | conns to 127.0.0.1:21080 = %s", psOut(fmt.Sprintf("(Get-NetTCPConnection -RemotePort 21080 -ErrorAction SilentlyContinue | Measure-Object).Count")))
	_ = net.IPv4len
}

func dumpLogs(t *testing.T, a *App) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	for _, l := range a.logs {
		if strings.Contains(l.Message, "TUN") || l.Level != "info" {
			t.Logf("LOG [%s] %s", l.Level, l.Message)
		}
	}
}

// TestLiveRouteOps 校验 CreateIpForwardEntry2 手工结构布局：写一条 TEST-NET-3 /32，回读，再删。
func TestLiveRouteOps(t *testing.T) {
	hop, ok := physHopFor(net.ParseIP("223.5.5.5"), 0)
	if !ok {
		t.Fatal("no phys hop")
	}
	_, n, _ := net.ParseCIDR("203.0.113.77/32")
	r := newRoute(*n, hop.NextHop, hop.IfIndex, bypassRouteMetric, "bypass")
	if err := (winRouteOps{}).AddRoute(r); err != nil {
		t.Fatalf("add %s: %v", r, err)
	}
	got := psOut("Get-NetRoute -DestinationPrefix 203.0.113.77/32 | % { '{0} nh={1} if={2} m={3} proto={4}' -f $_.DestinationPrefix,$_.NextHop,$_.ifIndex,$_.RouteMetric,$_.Protocol }")
	t.Logf("ROW | routeops add | %s | via %s", got, r)
	rows, _ := listRoutes2()
	found := false
	for _, row := range rows {
		if e, ok := row2ToEntry(row); ok && e.routeKey == r.routeKey && e.Metric == r.Metric {
			found = true
		}
	}
	t.Logf("ROW | routeops listRoutes2 sees it=%v (total %d rows)", found, len(rows))
	if err := (winRouteOps{}).DeleteRoute(r); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := (winRouteOps{}).DeleteRoute(r); err != errRouteNotFound {
		t.Fatalf("second delete = %v, want errRouteNotFound", err)
	}
	after := psOut("(Get-NetRoute -DestinationPrefix 203.0.113.77/32 -ErrorAction SilentlyContinue | Measure-Object).Count")
	t.Logf("ROW | routeops after delete count=%s", after)
	if !strings.Contains(got, "203.0.113.77/32") || after != "0" || !found {
		t.Fatal("route ops layout mismatch")
	}
	// 批量：5000 条绕过路由写入/删除耗时
	var plan []routeEntry
	for i, c := range cnCIDRs() {
		if i >= 5000 {
			break
		}
		plan = append(plan, newRoute(c, hop.NextHop, hop.IfIndex, bypassRouteMetric, "bypass"))
	}
	st := newTunRouteState()
	t0 := time.Now()
	added, _, err := st.sync(winRouteOps{}, plan)
	addDur := time.Since(t0)
	t1 := time.Now()
	removed, failed := st.clear(winRouteOps{})
	t.Logf("ROW | routeops bulk | added %d in %v err=%v | removed %d (failed %d) in %v", added, addDur.Round(time.Millisecond), err, removed, failed, time.Since(t1).Round(time.Millisecond))
	if sweepStaleBypassRoutes() != 0 {
		t.Log("sweep removed leftovers")
	}
}

func TestLiveWintun(t *testing.T) {
	loadWintunAPI()
	cb := windows.NewCallback(func(level uintptr, ts uint64, msg *uint16) uintptr {
		fmt.Printf("ROW | wintun log %d | %s\n", level, windows.UTF16PtrToString(msg))
		return 0
	})
	wintunMod.NewProc("WintunSetLogger").Call(cb)
	if os.Getenv("KN_ALT_GUID") == "1" {
		knTapGUID.Data1 = 0x6e4a2c32
	}
	idx, err := knTap.ensure()
	t.Logf("ROW | wintun ensure | idx=%d err=%v path=%s", idx, err, wintunModPath)
	if err == nil {
		t.Logf("ROW | configure | %v", configureTapAdapter(idx))
		t.Logf("ROW | iface | %s", psOut(fmt.Sprintf("Get-NetIPInterface -InterfaceIndex %d | %% { '{0} mtu={1} metric={2} auto={3}' -f $_.AddressFamily,$_.NlMtu,$_.InterfaceMetric,$_.AutomaticMetric }", idx)))
		knTap.closeSession()
	}
	t.Logf("ROW | pnp | %s", psOut("Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | ? { $_.FriendlyName -match 'KNcloud|Wintun' } | % { $_.FriendlyName + ' ' + $_.Status + ' ' + $_.InstanceId } | Out-String"))
}
