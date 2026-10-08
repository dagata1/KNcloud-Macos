//go:build e2elive && taptest

package main

// 实机 gVisor TUN 测试，网卡后端 = 已安装的 TAP-Windows "SSTAP 1"（KNCLOUD_TUN_DEVICE=tap）。
// go test -tags e2elive,taptest -c -o kntap.test.exe；每个 TestTap* 单独在计划任务里跑（≤4 分钟）。
// 结果逐行 "ROW |"。

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func curl4(url string, extra ...string) string {
	out, _ := curlNoProxy(url, append([]string{"-4"}, extra...)...)
	return extractIP(out)
}

func tapLocalDirectIP() string {
	for i := 0; i < 3; i++ {
		if ip := curl4("http://ip.3322.net"); ip != "FAIL" {
			return ip
		}
	}
	return machineDirectIP
}

type tapEnv struct {
	a          *App
	jp, sg     NodeItem
	local      string
	baseRoutes int
	baseDNS    string
}

func pickNodes(t *testing.T, a *App) (jp, sg NodeItem) {
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
	return
}

func tapState() string {
	return psOut("$a=Get-NetAdapter -InterfaceIndex 21; $ip=(Get-NetIPAddress -InterfaceIndex 21 -AddressFamily IPv4 -EA 0 | % { $_.IPAddress + '/' + $_.PrefixLength }) -join ','; " +
		"$v6=(Get-NetIPAddress -InterfaceIndex 21 -AddressFamily IPv6 -EA 0 | ? PrefixOrigin -ne 'WellKnown' | % IPAddress) -join ','; " +
		"$dns=(Get-DnsClientServerAddress -InterfaceIndex 21 -AddressFamily IPv4).ServerAddresses -join ','; " +
		"$r=(Get-NetRoute -InterfaceIndex 21 -EA 0 | ? Protocol -eq 'NetMgmt' | measure).Count; " +
		"'status={0} ipv4={1} v6extra={2} dns={3} netmgmtRoutes={4}' -f $a.Status,$ip,$v6,$dns,$r")
}

// routesNoTapLocal IPv4 路由数，不含 TAP 网卡自身的连接路由（句柄打开期间网卡是 Up 的，
// 172.19.0.0/30 等 Local 路由属于网卡本身，不是 TUN 写入的）
func routesNoTapLocal() int {
	var v int
	fmt.Sscan(psOut("(Get-NetRoute -AddressFamily IPv4 | ? { -not ($_.ifIndex -eq 21 -and $_.Protocol -eq 'Local') } | Measure-Object).Count"), &v)
	return v
}

func markedRoutes() string {
	return psOut("(Get-NetRoute -AddressFamily IPv4 | ? { $_.RouteMetric -eq 37 -or $_.RouteMetric -eq 4037 } | Measure-Object).Count")
}

func if9DNS() string {
	return psOut("(Get-DnsClientServerAddress -InterfaceIndex 9 -AddressFamily IPv4).ServerAddresses -join ','")
}

func setupTap(t *testing.T, policy string) *tapEnv {
	if os.Getenv("KNCLOUD_TUN_DEVICE") != "tap" {
		t.Fatal("KNCLOUD_TUN_DEVICE=tap required")
	}
	e := &tapEnv{}
	e.a, _ = setupLiveApp(t)
	e.jp, e.sg = pickNodes(t, e.a)
	e.local = tapLocalDirectIP()
	e.baseRoutes = routeCount4()
	e.baseDNS = if9DNS()
	t.Logf("ROW | baseline | local=%s routes=%d dns(if9)=%s | tap: %s | jp=%s:%d sg=%s:%d (%s)", e.local, e.baseRoutes, e.baseDNS, tapState(),
		e.jp.Address, e.jp.Port, e.sg.Address, e.sg.Port, e.jp.Protocol)
	e.a.mu.Lock()
	e.a.routingMode = policy
	e.a.mu.Unlock()
	if _, err := e.a.SelectNode(e.jp.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("core: %v", err)
	}
	t.Cleanup(func() {
		e.a.SimpleConnect(false)
		e.a.ToggleCore(false)
		res := testTap.Close()
		time.Sleep(time.Second)
		rc := routeCount4()
		dns := if9DNS()
		t.Logf("ROW | teardown | routes=%d (baseline %d) dns(if9)=%s (baseline %s) marked=%s | tap: %s | restore: %s",
			rc, e.baseRoutes, dns, e.baseDNS, markedRoutes(), tapState(), res)
		if rc != e.baseRoutes || dns != e.baseDNS {
			t.Errorf("not restored to baseline")
		}
		dumpLogs(t, e.a)
	})
	time.Sleep(800 * time.Millisecond)
	return e
}

func (e *tapEnv) start(t *testing.T, label string) {
	t0 := time.Now()
	on, err := e.a.SimpleConnect(true)
	e.a.mu.RLock()
	h, b, s := 0, 0, 0
	if e.a.tunRt != nil {
		h, b, s = e.a.tunRt.count("host"), e.a.tunRt.count("bypass"), e.a.tunRt.count("split")
	}
	e.a.mu.RUnlock()
	t.Logf("ROW | %s start TUN | %v on=%v err=%v | routes host=%d bypass=%d split=%d | tap: %s", label, time.Since(t0).Round(time.Millisecond), on, err, h, b, s, tapState())
	if !on || err != nil {
		dumpLogs(t, e.a)
		t.Fatalf("SimpleConnect: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
}

func (e *tapEnv) check(t *testing.T, label, wantForeign, wantCN string) {
	var f, c string
	for i := 0; i < 2; i++ {
		f, c = curl4("https://ifconfig.me/ip"), curl4("http://ip.3322.net")
		if f == wantForeign && c == wantCN {
			break
		}
		time.Sleep(time.Second)
	}
	st := "PASS"
	if f != wantForeign || c != wantCN {
		st = "FAIL"
		t.Errorf("%s: ifconfig.me=%s ip.3322.net=%s want %s / %s", label, f, c, wantForeign, wantCN)
	}
	t.Logf("ROW | %s | ifconfig.me=%s ip.3322.net=%s | want %s / %s | %s", label, f, c, wantForeign, wantCN, st)
}

func dnsMs(cmd string) string {
	return psOut("$t=Measure-Command { $r=" + cmd + " -ErrorAction SilentlyContinue }; $a=($r | ? IPAddress | select -First 1).IPAddress; '{0:N0}ms ans={1}' -f $t.TotalMilliseconds,$a")
}

// TestTapBasic：T1 连通、全局/绕过大陆/直连出口、DNS、UDP、策略热切换
func TestTapBasic(t *testing.T) {
	e := setupTap(t, "global")
	jpIP := nodeExitIP["日本"]
	e.check(t, "pre-TUN direct (core running, no sysproxy)", e.local, e.local)
	e.start(t, "global")
	e.check(t, "T1 global 日本", jpIP, jpIP)
	out6, _ := curlNoProxy("https://ifconfig.me/ip", "-6", "-m", "5")
	t.Logf("ROW | IPv6 probe global | curl -6 ifconfig.me => %q", out6)

	// DNS：系统解析器（网卡 DNS=198.18.0.2，metric 1），随机未缓存名
	for i := 0; i < 4; i++ {
		host := fmt.Sprintf("kn%d%d.qq.com", time.Now().UnixNano()%1000000, i)
		sys := dnsMs("Resolve-DnsName " + host + " -DnsOnly -Type A")
		direct := dnsMs(fmt.Sprintf("Resolve-DnsName www%d.baidu.com -Server %s -DnsOnly -Type A", i, tunDnsAddr))
		e.a.mu.RLock()
		active := int64(-1)
		if e.a.tap != nil {
			active = e.a.tap.dnsActive.Load()
		}
		e.a.mu.RUnlock()
		t.Logf("ROW | DNS #%d | system resolver uncached %s => %s | @198.18.0.2 www%d.baidu.com => %s | relay flows active=%d", i, host, sys, i, direct, active)
	}
	t.Logf("ROW | DNS resolver order | %s", psOut("Get-DnsClientServerAddress -AddressFamily IPv4 | ? ServerAddresses | % { '{0}:{1}' -f $_.InterfaceIndex,($_.ServerAddresses -join '/') } | Out-String"))
	// UDP：全局下直连 8.8.8.8:53（进 TUN → gVisor UDP → SOCKS UDP → 节点）
	for i := 0; i < 3; i++ {
		u := dnsMs(fmt.Sprintf("Resolve-DnsName www%d.google.com -Server 8.8.8.8 -DnsOnly -Type A", i))
		e.a.mu.RLock()
		ua := int64(-1)
		if e.a.tap != nil {
			ua = e.a.tap.udpActive.Load()
		}
		e.a.mu.RUnlock()
		t.Logf("ROW | UDP DNS 8.8.8.8 #%d | %s | udp flows active=%d", i, u, ua)
	}

	for _, m := range []string{"bypass-cn", "global", "bypass-cn"} {
		r0 := routeCount4()
		t1 := time.Now()
		ok, err := e.a.SetRoutingMode(m)
		d := time.Since(t1).Round(time.Millisecond)
		r1 := routeCount4()
		t.Logf("ROW | policy → %s while TUN | %v ok=%v err=%v tun=%v | routes %d → %d", m, d, ok, err, e.a.GetCoreStatus().TunRunning, r0, r1)
		if m == "global" {
			e.check(t, "global 日本 (live switch)", jpIP, jpIP)
		} else {
			e.check(t, "bypass-cn 日本 (live switch)", jpIP, e.local)
			t.Logf("ROW | bypass-cn DNS | %s", dnsMs(fmt.Sprintf("Resolve-DnsName kn%d.taobao.com -DnsOnly -Type A", time.Now().UnixNano()%1000000)))
		}
	}
	t1 := time.Now()
	ok, err := e.a.SetRoutingMode("direct")
	t.Logf("ROW | policy → direct | %v ok=%v err=%v tun=%v routes=%d tap: %s", time.Since(t1).Round(time.Millisecond), ok, err, e.a.GetCoreStatus().TunRunning, routeCount4(), tapState())
	e.check(t, "direct", e.local, e.local)
}

// TestTapSwap：TUN 运行中 日本↔新加坡 10 次，3 路 200ms 轮询 ifconfig.me，不得出现本机 IP
func TestTapSwap(t *testing.T) {
	policy := os.Getenv("LIVE_POLICY")
	if policy == "" {
		policy = "global"
	}
	e := setupTap(t, policy)
	jpIP, sgIP := nodeExitIP["日本"], nodeExitIP["新加坡"]
	e.start(t, policy)
	e.check(t, "swap pre "+policy, jpIP, map[bool]string{true: jpIP, false: e.local}[policy == "global"])
	ka := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 8 * time.Second}
	t.Logf("ROW | keep-alive before | %s", getIP(ka, foreignEcho, false))
	var mu sync.Mutex
	type sample struct {
		at time.Time
		ip string
	}
	var seen []sample
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for p := 0; p < 3; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			time.Sleep(time.Duration(p) * 70 * time.Millisecond)
			for {
				select {
				case <-stop:
					return
				default:
				}
				ip := curl4("https://ifconfig.me/ip", "-m", "3")
				mu.Lock()
				seen = append(seen, sample{time.Now(), ip})
				mu.Unlock()
				time.Sleep(200 * time.Millisecond)
			}
		}(p)
	}
	g0 := runtime.NumGoroutine()
	h0 := procStats()
	order := []NodeItem{e.sg, e.jp, e.sg, e.jp, e.sg, e.jp, e.sg, e.jp, e.sg, e.jp}
	var swapDur, swapAt []string
	for i, n := range order {
		time.Sleep(2500 * time.Millisecond)
		t1 := time.Now()
		_, err := e.a.SelectNode(n.ID)
		swapDur = append(swapDur, time.Since(t1).Round(time.Millisecond).String())
		mu.Lock()
		swapAt = append(swapAt, t1.Sub(seen[0].at).Round(100*time.Millisecond).String())
		mu.Unlock()
		time.Sleep(1200 * time.Millisecond)
		want := nodeExitIP[nodeKey(n.Name)]
		kaIP := getIP(ka, foreignEcho, false)
		e.a.mu.RLock()
		var hosts []string
		for _, r := range e.a.tunRt.entries("host") {
			hosts = append(hosts, u32ToIP(r.Dest).String())
		}
		e.a.mu.RUnlock()
		st := "PASS"
		if err != nil || kaIP != want {
			st = "FAIL"
			t.Errorf("switch %d to %s: err=%v keepalive=%s want %s", i, n.Name, err, kaIP, want)
		}
		t.Logf("ROW | swap %d →%s | %s err=%v | keep-alive=%s want=%s | host /32s=%v | %s", i, n.Name, swapDur[i], err, kaIP, want, hosts, st)
	}
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
	leaks, fails, jpN, sgN := 0, 0, 0, 0
	var leakAt []string
	t00 := seen[0].at
	for _, s := range seen {
		switch s.ip {
		case e.local:
			leaks++
			leakAt = append(leakAt, s.at.Sub(t00).Round(time.Millisecond).String())
		case jpIP:
			jpN++
		case sgIP:
			sgN++
		default:
			fails++
		}
	}
	st := "PASS"
	if leaks > 0 {
		st = "FAIL"
		t.Errorf("local IP leaked %d times during node switches at %v", leaks, leakAt)
	}
	t.Logf("ROW | swap poll (3×200ms) %s | samples=%d jp=%d sg=%d localIPleaks=%d failed/timeouts=%d | swap durations %v | %s", policy, len(seen), jpN, sgN, leaks, fails, swapDur, st)
	var failAt []string
	for _, s := range seen {
		if s.ip != jpIP && s.ip != sgIP && s.ip != e.local {
			failAt = append(failAt, s.at.Sub(t00).Round(100*time.Millisecond).String())
		}
	}
	t.Logf("ROW | swap poll failures at (since first sample) | %v | swaps at %v", failAt, swapAt)
	ka.CloseIdleConnections()
	time.Sleep(3 * time.Second)
	t.Logf("ROW | proc after swaps (+3s) | goroutines %d→%d handles/threads %s→%s sockets %s", g0, runtime.NumGoroutine(), h0, procStats(), sockCounts())
	t.Logf("ROW | goroutines top | %s", goroutineSummary(12))
	time.Sleep(12 * time.Second)
	t.Logf("ROW | proc after swaps (+15s) | goroutines %d handles/threads %s sockets %s", runtime.NumGoroutine(), procStats(), sockCounts())
	t.Logf("ROW | goroutines top (+15s) | %s", goroutineSummary(12))
}

// goroutineSummary 按「顶层函数 + created by」聚合当前协程，返回数量最多的 n 组
func goroutineSummary(n int) string {
	buf := make([]byte, 8<<20)
	buf = buf[:runtime.Stack(buf, true)]
	cnt := map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		lines := strings.Split(strings.TrimSpace(g), "\n")
		if len(lines) < 2 {
			continue
		}
		top := strings.TrimSpace(lines[1])
		if i := strings.LastIndex(top, "("); i > 0 {
			top = top[:i]
		}
		cr := ""
		for _, l := range lines {
			if strings.HasPrefix(l, "created by ") {
				cr = strings.TrimPrefix(strings.Fields(l)[2], "")
			}
		}
		cnt[top+" <- "+cr]++
	}
	type kv struct {
		k string
		v int
	}
	var kvs []kv
	for k, v := range cnt {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v })
	var out []string
	for i := 0; i < len(kvs) && i < n; i++ {
		out = append(out, fmt.Sprintf("%d× %s", kvs[i].v, kvs[i].k))
	}
	return strings.Join(out, " || ")
}

func sockCounts() string {
	pid := os.Getpid()
	return psOut(fmt.Sprintf("'tcp={0} udp={1}' -f (Get-NetTCPConnection -OwningProcess %d -EA 0 | measure).Count,(Get-NetUDPEndpoint -OwningProcess %d -EA 0 | measure).Count", pid, pid))
}

// TestTapCycles：20 次开关，看协程/句柄/socket/路由是否回落
func TestTapCycles(t *testing.T) {
	e := setupTap(t, "global")
	jpIP := nodeExitIP["日本"]
	// 预热一次（让 Xray/DLL/首次分配稳定）
	e.start(t, "warmup")
	e.check(t, "warmup global", jpIP, jpIP)
	e.a.SimpleConnect(false)
	time.Sleep(2 * time.Second)
	runtime.GC()
	g0, h0, s0 := runtime.NumGoroutine(), procStats(), sockCounts()
	t.Logf("ROW | cycles before | goroutines=%d handles/threads=%s sockets %s routes=%d", g0, h0, s0, routeCount4())
	t.Logf("ROW | goroutines top before cycles | %s", goroutineSummary(8))
	r0 := routeCount4()
	var durs []string
	bad := 0
	for i := 0; i < 20; i++ {
		policy := "global"
		if i%5 == 4 {
			policy = "bypass-cn"
		}
		e.a.mu.Lock()
		e.a.routingMode = policy
		e.a.mu.Unlock()
		t1 := time.Now()
		on, err := e.a.SimpleConnect(true)
		up := time.Since(t1)
		if !on || err != nil {
			t.Errorf("cycle %d start: %v", i, err)
			bad++
			continue
		}
		if i%5 == 0 || i%5 == 4 {
			got := curl4("https://ifconfig.me/ip", "-m", "6")
			if got != jpIP {
				t.Errorf("cycle %d (%s): ifconfig.me=%s", i, policy, got)
			}
		}
		t2 := time.Now()
		e.a.SimpleConnect(false)
		down := time.Since(t2)
		rc := routeCount4()
		if rc != r0 {
			t.Errorf("cycle %d: routes=%d after stop (before cycles %d)", i, rc, r0)
			bad++
		}
		durs = append(durs, fmt.Sprintf("%s:%v/%v", policy[:1], up.Round(time.Millisecond), down.Round(time.Millisecond)))
	}
	time.Sleep(3 * time.Second)
	runtime.GC()
	time.Sleep(time.Second)
	g1, h1, s1 := runtime.NumGoroutine(), procStats(), sockCounts()
	t.Logf("ROW | cycles after 20 | goroutines %d→%d handles/threads %s→%s sockets %s→%s routes=%d tap: %s | bad=%d", g0, g1, h0, h1, s0, s1, routeCount4(), tapState(), bad)
	t.Logf("ROW | cycle up/down durations | %v", durs)
	t.Logf("ROW | goroutines top after cycles | %s", goroutineSummary(12))
	for w := 1; w <= 3; w++ {
		time.Sleep(30 * time.Second)
		runtime.GC()
		t.Logf("ROW | cycles after +%ds idle | goroutines=%d handles/threads=%s sockets %s", 3+30*w, runtime.NumGoroutine(), procStats(), sockCounts())
	}
	g1 = runtime.NumGoroutine()
	t.Logf("ROW | goroutines top after idle | %s", goroutineSummary(6))
	if g1 > g0+5 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		os.WriteFile(filepath.Join(os.Getenv("KN_OUT"), "goroutines.txt"), buf[:n], 0644)
		t.Errorf("goroutine leak: %d → %d", g0, g1)
	}
}

// failingOps 第 failAt 次 AddRoute 返回错误（模拟写路由失败）
type failingOps struct {
	inner  routeOps
	failAt int64
	n      atomic.Int64
}

func (f *failingOps) AddRoute(r routeEntry) error {
	if f.n.Add(1) == f.failAt {
		return fmt.Errorf("injected AddRoute failure on %s", r)
	}
	return f.inner.AddRoute(r)
}
func (f *failingOps) DeleteRoute(r routeEntry) error { return f.inner.DeleteRoute(r) }

// TestTapFaults：路由写入失败回滚 + kill -9 后残留与清理
func TestTapFaults(t *testing.T) {
	e := setupTap(t, "bypass-cn")
	jpIP := nodeExitIP["日本"]
	// F1 开 TUN 时第 3000 条路由写失败 → 整体回滚到基线，TUN 未开
	base := routesNoTapLocal() // 不含 TAP 自身连接路由的基线（网卡打开后会多出 172.19.0.0/30 等）
	e.a.mu.Lock()
	e.a.tunOps = &failingOps{inner: winRouteOps{}, failAt: 3000}
	e.a.mu.Unlock()
	on, err := e.a.SimpleConnect(true)
	rc := routesNoTapLocal()
	st := "PASS"
	if on || err == nil || rc != base || markedRoutes() != "0" {
		st = "FAIL"
		t.Errorf("F1 rollback: on=%v err=%v routes=%d", on, err, rc)
	}
	t.Logf("ROW | F1 start with route #3000 failing | on=%v err=%v | routes(excl. TAP local)=%d (baseline %d) marked=%s if9dns=%s | tap: %s | %s", on, err, rc, base, markedRoutes(), if9DNS(), tapState(), st)
	e.check(t, "F1 after rollback (direct)", e.local, e.local)

	// F2 TUN（全局）运行中切到绕过大陆，第 2000 条失败 → 保持全局，路由不变
	e.a.mu.Lock()
	e.a.tunOps = nil
	e.a.routingMode = "global"
	e.a.mu.Unlock()
	e.start(t, "F2 global")
	r0 := routeCount4()
	e.a.mu.Lock()
	e.a.tunOps = &failingOps{inner: winRouteOps{}, failAt: 2000}
	e.a.mu.Unlock()
	ok, err := e.a.SetRoutingMode("bypass-cn")
	r1 := routeCount4()
	mode := e.a.GetCoreStatus().RoutingMode
	st = "PASS"
	if ok || err == nil || r1 != r0 || mode != "global" || !e.a.GetCoreStatus().TunRunning {
		st = "FAIL"
		t.Errorf("F2: ok=%v err=%v routes %d→%d mode=%s", ok, err, r0, r1, mode)
	}
	t.Logf("ROW | F2 policy switch with route #2000 failing | ok=%v err=%v routes %d→%d mode=%s tun=%v | %s", ok, err, r0, r1, mode, e.a.GetCoreStatus().TunRunning, st)
	e.check(t, "F2 still global", jpIP, jpIP)
	e.a.mu.Lock()
	e.a.tunOps = nil
	e.a.mu.Unlock()
	e.a.SimpleConnect(false)
	e.a.ToggleCore(false)
	testTap.Close()
	time.Sleep(time.Second)
	t.Logf("ROW | F2 after stop | routes=%d tap: %s", routeCount4(), tapState())

	// F3 子进程开 TUN（绕过大陆）后 kill -9
	exe, _ := os.Executable()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(exe, "-test.run", "^TestTapChildHold$", "-test.v", "-test.timeout", "120s")
	cmd.Env = append(os.Environ(), "KN_CHILD_READY="+ready)
	logf, _ := os.Create(filepath.Join(os.Getenv("KN_OUT"), "child.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	rc = routeCount4()
	t.Logf("ROW | F3 child TUN up | pid=%d routes=%d | tap: %s | child ifconfig=%s", cmd.Process.Pid, rc, tapState(), curl4("https://ifconfig.me/ip", "-m", "6"))
	exec.Command("taskkill", "/F", "/PID", fmt.Sprint(cmd.Process.Pid)).Run()
	cmd.Wait()
	logf.Close()
	time.Sleep(1500 * time.Millisecond)
	t.Logf("ROW | F3 after kill -9 | routes=%d marked=%s if9dns=%s | tap: %s | ifconfig=%s ip.3322=%s", routeCount4(), markedRoutes(), if9DNS(), tapState(),
		curl4("https://ifconfig.me/ip", "-m", "5"), curl4("http://ip.3322.net", "-m", "5"))
	// 清理路径：同一程序再开一次（开前 sweep 残留绕过路由）再关
	if ok, err := e.a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("core: %v", err)
	}
	e.a.mu.Lock()
	e.a.routingMode = "global"
	e.a.mu.Unlock()
	e.start(t, "F3 cleanup-run global")
	e.check(t, "F3 cleanup-run global", jpIP, jpIP)
	e.a.SimpleConnect(false)
	time.Sleep(time.Second)
	rc = routesNoTapLocal()
	st = "PASS"
	if rc != base || markedRoutes() != "0" {
		st = "FAIL"
		t.Errorf("F3 residual routes after cleanup path: %d (baseline %d)", rc, base)
	}
	t.Logf("ROW | F3 after cleanup path | routes(excl. TAP local)=%d (baseline %d) marked=%s if9dns=%s | tap: %s | %s", rc, base, markedRoutes(), if9DNS(), tapState(), st)
	if rc != base {
		t.Logf("ROW | F3 residual detail | %s", psOut("Get-NetRoute -AddressFamily IPv4 | ? { $_.ifIndex -eq 21 -or $_.RouteMetric -eq 37 -or $_.RouteMetric -eq 4037 -or $_.RouteMetric -eq 1 } | select -First 20 | % { $_.DestinationPrefix + ' if' + $_.ifIndex + ' m' + $_.RouteMetric + ' ' + $_.Protocol } | Out-String"))
	}
}

// TestTapChildHold 子进程：开 TUN（绕过大陆）后写 ready 并挂起，等父进程 kill -9。
func TestTapChildHold(t *testing.T) {
	ready := os.Getenv("KN_CHILD_READY")
	if ready == "" {
		t.Skip("child only")
	}
	a, _ := setupLiveApp(t)
	jp, _ := pickNodes(t, a)
	a.mu.Lock()
	a.routingMode = "bypass-cn"
	a.mu.Unlock()
	a.SelectNode(jp.ID)
	a.ToggleCore(true)
	on, err := a.SimpleConnect(true)
	t.Logf("child TUN on=%v err=%v", on, err)
	os.WriteFile(ready, []byte("1"), 0644)
	time.Sleep(100 * time.Second)
}

func curlSpeed(proxy, url string, maxSec int) string {
	args := []string{"-4", "-s", "-o", "NUL", "-m", fmt.Sprint(maxSec), "-w", "bytes=%{size_download} time=%{time_total} speed=%{speed_download} ttfb=%{time_starttransfer}"}
	if proxy != "" {
		args = append(args, "-x", proxy)
	} else {
		args = append(args, "--noproxy", "*")
	}
	args = append(args, url)
	out, _ := exec.Command("curl.exe", args...).Output()
	return strings.TrimSpace(string(out))
}

// TestTapPerf：同一节点 TUN（全局）vs SOCKS（系统代理模式）下载速度，交替 2 轮
func TestTapPerf(t *testing.T) {
	e := setupTap(t, "global")
	const dl = "https://speed.cloudflare.com/__down?bytes=99000000"
	sec := 40
	for round := 0; round < 2; round++ {
		t.Logf("ROW | perf round %d SOCKS socks5h://127.0.0.1:21080 | %s", round, curlSpeed("socks5h://127.0.0.1:21080", dl, sec))
		e.start(t, fmt.Sprintf("perf round %d", round))
		t.Logf("ROW | perf round %d TUN global | %s", round, curlSpeed("", dl, sec))
		e.a.SimpleConnect(false)
		time.Sleep(time.Second)
	}
	t.Logf("ROW | perf direct (no proxy, reference) | %s", curlSpeed("", dl, 20))
}

// dnsQueryA 手工 DNS A 查询（UDP），返回耗时与应答码
func dnsQueryA(server, name string, timeout time.Duration) (time.Duration, int, error) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	c, err := net.Dial("udp", server)
	if err != nil {
		return 0, -1, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	t0 := time.Now()
	if _, err := c.Write(q); err != nil {
		return 0, -1, err
	}
	b := make([]byte, 1500)
	n, err := c.Read(b)
	if err != nil {
		return time.Since(t0), -1, err
	}
	if n < 4 {
		return time.Since(t0), -1, fmt.Errorf("short")
	}
	return time.Since(t0), int(b[3] & 0xf), nil
}

var dnsNames = []string{"www.jd.com", "www.zhihu.com", "www.bilibili.com", "www.douban.com", "www.163.com",
	"www.github.com", "www.wikipedia.org", "www.reddit.com", "www.bbc.co.uk", "www.nytimes.com",
	"www.sohu.com", "www.ctrip.com", "www.apple.com", "www.mozilla.org", "www.cloudflare.com"}

func pktmonStart() {
	exec.Command("pktmon", "stop").Run()
	exec.Command("pktmon", "filter", "remove").Run()
	exec.Command("pktmon", "filter", "add", "ISP1", "-i", "211.136.17.107", "-p", "53").Run()
	exec.Command("pktmon", "filter", "add", "ISP2", "-i", "211.136.20.203", "-p", "53").Run()
	exec.Command("pktmon", "start", "-c", "-o", "--comp", "nics").Run()
}

// pktmonStop 返回发往运营商 DNS（物理网卡 DHCP DNS）的包计数摘要
func pktmonStop() string {
	out, _ := exec.Command("pktmon", "counters").CombinedOutput()
	exec.Command("pktmon", "stop").Run()
	exec.Command("pktmon", "filter", "remove").Run()
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && (strings.ContainsAny(l, "0123456789")) {
			keep = append(keep, strings.Join(strings.Fields(l), " "))
		}
	}
	return strings.Join(keep, " / ")
}

func sysLookups(t *testing.T, label string, names []string) {
	exec.Command("ipconfig", "/flushdns").Run()
	var ds []time.Duration
	var errs int
	for _, n := range names {
		t0 := time.Now()
		_, err := net.LookupHost(n)
		d := time.Since(t0)
		if err != nil {
			errs++
		}
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	t.Logf("ROW | %s | system resolver %d uncached names | min=%v median=%v p90=%v max=%v errors=%d", label, len(names),
		ds[0].Round(time.Millisecond), ds[len(ds)/2].Round(time.Millisecond), ds[len(ds)*9/10].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond), errs)
}

func rawQueries(t *testing.T, label, server string) {
	var ds []time.Duration
	var bad []string
	for i := 0; i < 10; i++ {
		d, rc, err := dnsQueryA(server, fmt.Sprintf("kn%d%d.example.com", time.Now().UnixNano()%1000000, i), 3*time.Second)
		if err != nil || (rc != 0 && rc != 3) {
			bad = append(bad, fmt.Sprintf("rc=%d err=%v", rc, err))
			continue
		}
		ds = append(ds, d)
	}
	if len(ds) == 0 {
		t.Logf("ROW | %s | raw UDP A query @%s | all failed %v", label, server, bad)
		return
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	t.Logf("ROW | %s | raw UDP A query @%s ×10 random | min=%v median=%v max=%v failures=%v", label, server,
		ds[0].Round(time.Millisecond), ds[len(ds)/2].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond), bad)
}

// TestTapDNS：DNS 经 TUN 的延迟 + 是否回落到物理网卡 DNS（pktmon 计数发往运营商 DNS 的包）
func TestTapDNS(t *testing.T) {
	e := setupTap(t, "global")
	defer pktmonStop()
	// 对照：TUN 关闭时系统解析器走运营商 DNS（pktmon 应计到包）
	rawQueries(t, "control TUN off", "223.5.5.5:53")
	pktmonStart()
	sysLookups(t, "control TUN off", dnsNames[:5])
	t.Logf("ROW | control TUN off | pktmon packets to ISP DNS | %s", pktmonStop())

	e.start(t, "dns global")
	rawQueries(t, "TUN global", tunDnsAddr+":53")
	rawQueries(t, "TUN global (8.8.8.8 has a physical /32 DNS hop)", "8.8.8.8:53")
	rawQueries(t, "TUN global (UDP via node)", "9.9.9.9:53")
	rawQueries(t, "TUN global (UDP via node)", "1.0.0.1:53")
	t.Logf("ROW | WFP filters | %s", psOut("netsh wfp show filters file=$env:TEMP\\knwfp.xml | Out-Null; [xml]$x=Get-Content $env:TEMP\\knwfp.xml; $x.wfpdiag.filters.item | ? { $_.displayData.name -like 'KNcloud*' } | % { $_.layerKey + ' ' + $_.action.type + ' ' + (($_.filterCondition.item | % { $_.fieldKey + '=' + $_.conditionValue.uint16 + $_.conditionValue.uint32 }) -join '&') } | Out-String"))
	pktmonStart()
	sysLookups(t, "TUN global", dnsNames)
	t.Logf("ROW | TUN global | pktmon packets to ISP DNS | %s", pktmonStop())

	// 直连 ISP DNS（非本进程）应被拦截
	if _, rc, err := dnsQueryA("211.136.17.107:53", "www.qq.com", 2*time.Second); true {
		t.Logf("ROW | TUN global | in-process query to ISP DNS 211.136.17.107 (own process is permitted) | rc=%d err=%v", rc, err)
	}
	t.Logf("ROW | TUN global | nslookup.exe www.qq.com 211.136.17.107 (other process, should be blocked) | %s", psOut("$o = nslookup -timeout=2 www.qq.com 211.136.17.107 2>&1 | Out-String; $o.Trim() -replace '\\s+',' '"))
	e.a.SetRoutingMode("bypass-cn")
	time.Sleep(500 * time.Millisecond)
	pktmonStart()
	sysLookups(t, "TUN bypass-cn", dnsNames)
	t.Logf("ROW | TUN bypass-cn | pktmon packets to ISP DNS | %s", pktmonStop())
	rawQueries(t, "TUN bypass-cn", tunDnsAddr+":53")
	t.Logf("ROW | v6 route diag | %s", psOut("Get-NetRoute -InterfaceIndex 21 -AddressFamily IPv6 -EA 0 | % { $_.DestinationPrefix + ' via ' + $_.NextHop } | Out-String; netsh interface ipv6 add route 2000::/3 fdfe:dcba:9876::1 interface=21 metric=5 store=active publish=no; netsh interface ipv6 show route interface=21"))
}

func tapCounters() string {
	d := testTap
	return fmt.Sprintf("rx=%d/%dB rxErr=%d tx=%d/%dB txErr=%d txMax=%d", d.RxPkts.Load(), d.RxBytes.Load(), d.RxErr.Load(), d.TxPkts.Load(), d.TxBytes.Load(), d.TxErr.Load(), d.TxMax.Load())
}

func gvStats(a *App) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.tap == nil {
		return "no stack"
	}
	st := a.tap.stack.Stats()
	return fmt.Sprintf("tcp tlpRec=%d sackRec=%d fastRec=%d spurious=%d | retrans=%d fastRetrans=%d timeouts=%d sendErr=%d csumErr=%d invalidSeg=%d segSent=%d segRcvd=%d | ip rcvd=%d malformed=%d outErr=%d | nic tx=%d rx=%d",
		st.TCP.TLPRecovery.Value(), st.TCP.SACKRecovery.Value(), st.TCP.FastRecovery.Value(), st.TCP.SpuriousRecovery.Value(),
		st.TCP.Retransmits.Value(), st.TCP.FastRetransmit.Value(), st.TCP.Timeouts.Value(), st.TCP.SegmentSendErrors.Value(), st.TCP.ChecksumErrors.Value(), st.TCP.InvalidSegmentsReceived.Value(),
		st.TCP.SegmentsSent.Value(), st.TCP.ValidSegmentsReceived.Value(),
		st.IP.PacketsReceived.Value(), st.IP.MalformedPacketsReceived.Value(), st.IP.OutgoingPacketErrors.Value(),
		st.NICs.Tx.Packets.Value(), st.NICs.Rx.Packets.Value())
}

// TestTapDiag：TUN 下载慢的诊断（链路计数、gVisor TCP 统计、TUN 开启时 SOCKS 对照）
func TestTapDiag(t *testing.T) {
	e := setupTap(t, os.Getenv("LIVE_POLICY"))
	dl := "https://speed.cloudflare.com/__down?bytes=99000000"
	if u := os.Getenv("KN_DL"); u != "" {
		dl = u
	}
	t.Logf("ROW | diag SOCKS 15s (TUN off) | %s", curlSpeed("socks5h://127.0.0.1:21080", dl, 15))
	e.start(t, "diag")
	t.Logf("ROW | diag t0 | link %s | %s", tapCounters(), gvStats(e.a))
	time.Sleep(10 * time.Second)
	t.Logf("ROW | diag idle 10s | link %s | %s", tapCounters(), gvStats(e.a))
	t.Logf("ROW | diag SOCKS 15s (TUN on) | %s", curlSpeed("socks5h://127.0.0.1:21080", dl, 15))
	t.Logf("ROW | diag after SOCKS | link %s | %s", tapCounters(), gvStats(e.a))
	done := make(chan string)
	go func() { done <- curlSpeed("", dl, 20) }()
	for i := 0; i < 4; i++ {
		time.Sleep(5 * time.Second)
		t.Logf("ROW | diag TUN dl +%ds | link %s | %s | tcp flows=%d udp flows=%d", 5*(i+1), tapCounters(), gvStats(e.a), e.a.tap.tcpActive.Load(), e.a.tap.udpActive.Load())
	}
	t.Logf("ROW | diag TUN 20s | %s", <-done)
	t.Logf("ROW | diag top talkers | %s", psOut("Get-NetTCPConnection -State Established -EA 0 | ? { $_.RemoteAddress -notmatch '^(127\\.|::1|0\\.)' } | group OwningProcess | sort Count -desc | select -First 6 | % { '{0}:{1}' -f (Get-Process -Id $_.Name -EA 0).Name,$_.Count } | Out-String"))
	t.Logf("ROW | diag udp talkers | %s", psOut("Get-NetUDPEndpoint -EA 0 | ? { $_.LocalAddress -notmatch '^(127\\.|::1)' } | group OwningProcess | sort Count -desc | select -First 6 | % { '{0}:{1}' -f (Get-Process -Id $_.Name -EA 0).Name,$_.Count } | Out-String"))
}

func curlW(proxy, url string, maxSec int) string {
	args := []string{"-4", "-s", "-o", "NUL", "-m", fmt.Sprint(maxSec), "-w", "rc=%{exitcode} ip=%{remote_ip} code=%{http_code} bytes=%{size_download} t=%{time_total} speed=%{speed_download} conn=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer}"}
	if proxy != "" {
		args = append(args, "-x", proxy)
	} else {
		args = append(args, "--noproxy", "*")
	}
	args = append(args, url)
	out, _ := exec.Command("curl.exe", args...).Output()
	return strings.TrimSpace(string(out))
}

// TestTapDiag2：多个下载源，TUN vs SOCKS，逐个附 gVisor 统计增量
func TestTapDiag2(t *testing.T) {
	e := setupTap(t, "global")
	urls := []string{
		"https://speed.cloudflare.com/__down?bytes=20000000",
		"https://proof.ovh.net/files/10Mb.dat",
	}
	t.Logf("ROW | d2 SOCKS | %s | %s", urls[0], curlW("socks5h://127.0.0.1:21080", urls[0], 10))
	for _, mtu := range []string{"1500", "1280"} {
		os.Setenv("KN_TAP_MTU", mtu)
		e.start(t, "d2 mtu "+mtu)
		for _, u := range urls[:1] {
			b := gvStats(e.a)
			l := tapCounters()
			a0 := adapterStats()
			r := curlW("", u, 12)
			t.Logf("ROW | d2 TUN mtu %s | %s | %s\n      before: link %s | %s | nic %s\n      after:  link %s | %s | nic %s", mtu, u, r, l, b, a0, tapCounters(), gvStats(e.a), adapterStats())
		}
		e.a.SimpleConnect(false)
		time.Sleep(time.Second)
	}

}

func adapterStats() string {
	row := windows.MibIfRow2{InterfaceIndex: testTap.ifIdx}
	if err := windows.GetIfEntry2Ex(0, &row); err != nil {
		return err.Error()
	}
	return fmt.Sprintf("inUcast=%d inDisc=%d inErr=%d inUnknownProto=%d outUcast=%d outDisc=%d outErr=%d", row.InUcastPkts, row.InDiscards, row.InErrors, row.InUnknownProtos, row.OutUcastPkts, row.OutDiscards, row.OutErrors)
}

// TestTapCapture：TUN 下载期间在 TAP 网卡上 pktmon 抓包（导出 pcapng 供离线分析）
func TestTapCapture(t *testing.T) {
	e := setupTap(t, "global")
	defer pktmonStop()
	e.start(t, "cap")
	out := os.Getenv("KN_OUT")
	exec.Command("pktmon", "stop").Run()
	exec.Command("pktmon", "filter", "remove").Run()
	exec.Command("pktmon", "filter", "add", "TAPCAP", "-i", "172.19.0.2", "-t", "TCP").Run()
	etl := filepath.Join(out, "cap.etl")
	os.Remove(etl)
	o, err := exec.Command("pktmon", "start", "-c", "--comp", "nics", "--pkt-size", "96", "-f", etl).CombinedOutput()
	t.Logf("ROW | pktmon start | %v %s", err, strings.TrimSpace(string(o)))
	b := gvStats(e.a)
	r := curlW("", "https://speed.cloudflare.com/__down?bytes=20000000", 8)
	o, err = exec.Command("pktmon", "stop").CombinedOutput()
	t.Logf("ROW | cap TUN | %s | before %s | after %s | stop %v", r, b, gvStats(e.a), err)
	o, err = exec.Command("pktmon", "etl2pcap", etl, "-o", filepath.Join(out, "cap.pcapng")).CombinedOutput()
	t.Logf("ROW | etl2pcap | %v %s", err, strings.TrimSpace(string(o)))
	exec.Command("pktmon", "filter", "remove").Run()
}

func nxLookups(t *testing.T, label string) {
	exec.Command("ipconfig", "/flushdns").Run()
	var parts []string
	for i := 0; i < 3; i++ {
		n := fmt.Sprintf("kn%d%d.qq.com", time.Now().UnixNano()%10000000, i)
		t0 := time.Now()
		_, err := net.LookupHost(n)
		parts = append(parts, fmt.Sprintf("%v(%v)", time.Since(t0).Round(time.Millisecond), err != nil))
	}
	t.Logf("ROW | %s | NXDOMAIN system lookups | %v", label, parts)
}

const dnsPolicyKey = `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`

// TestTapDNS2：WFP 拦截下 NXDOMAIN 变慢的实验（SMHNR 策略开/关、拦截开/关）
func TestTapDNS2(t *testing.T) {
	e := setupTap(t, "global")
	defer exec.Command("reg", "delete", dnsPolicyKey, "/f").Run()
	defer pktmonStop()
	nxLookups(t, "P0 TUN off")
	e.start(t, "dns2")
	phase := func(label string) {
		pktmonStart()
		nxLookups(t, label)
		sysLookups(t, label, dnsNames[:8])
		t.Logf("ROW | %s | pktmon ISP DNS | %s", label, pktmonStop())
	}
	phase("P1 guard on")
	exec.Command("reg", "add", dnsPolicyKey, "/v", "DisableSmartNameResolution", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	exec.Command("reg", "add", dnsPolicyKey, "/v", "DisableParallelAandAAAA", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	time.Sleep(3 * time.Second)
	phase("P2 guard on + SMHNR off")
	e.a.mu.Lock()
	g := e.a.tunDNSGuard
	e.a.tunDNSGuard = nil
	e.a.mu.Unlock()
	g.Close()
	phase("P3 guard off + SMHNR off")
	exec.Command("reg", "delete", dnsPolicyKey, "/f").Run()
	time.Sleep(3 * time.Second)
	phase("P4 guard off + SMHNR default")
}

const nrptKey = `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\KNcloudTunTest`

// TestTapDNS3：NRPT「.」→ 198.18.0.2 能否让 NXDOMAIN 不再等其他网卡（WFP 拦截保持开启）
func TestTapDNS3(t *testing.T) {
	e := setupTap(t, "global")
	defer exec.Command("reg", "delete", nrptKey, "/f").Run()
	defer pktmonStop()
	e.start(t, "dns3")
	phase := func(label string) {
		pktmonStart()
		nxLookups(t, label)
		sysLookups(t, label, dnsNames[:8])
		t.Logf("ROW | %s | pktmon ISP DNS | %s", label, pktmonStop())
	}
	for _, a := range [][]string{
		{"/v", "Name", "/t", "REG_MULTI_SZ", "/d", "."},
		{"/v", "GenericDNSServers", "/t", "REG_SZ", "/d", tunDnsAddr},
		{"/v", "ConfigOptions", "/t", "REG_DWORD", "/d", "8"},
		{"/v", "Version", "/t", "REG_DWORD", "/d", "2"},
		{"/v", "IPSECCARestriction", "/t", "REG_SZ", "/d", ""},
	} {
		o, err := exec.Command("reg", append([]string{"add", nrptKey}, append(a, "/f")...)...).CombinedOutput()
		if err != nil {
			t.Logf("reg add %v: %v %s", a, err, o)
		}
	}
	exec.Command("ipconfig", "/flushdns").Run()
	time.Sleep(2 * time.Second)
	t.Logf("ROW | NRPT visible | %s", psOut("Get-DnsClientNrptPolicy | % { $_.Namespace + ' -> ' + ($_.NameServers -join ',') } | Out-String"))
	phase("N1 guard on + NRPT(reg) .")
	o, _ := exec.Command("reg", "delete", nrptKey, "/f").CombinedOutput()
	exec.Command("ipconfig", "/flushdns").Run()
	time.Sleep(2 * time.Second)
	t.Logf("ROW | NRPT removed | %s | %s", strings.TrimSpace(string(o)), psOut("(Get-DnsClientNrptPolicy | measure).Count"))
	phase("N2 guard on, NRPT removed")
}
