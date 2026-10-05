package main

// KNcloud-WIN.exe --tun-selftest：简易模式（SSTap 方案）链路自检，需管理员运行。
//
// 流程：连接 → 校验虚拟网卡/DNS 劫持路由/分流路由 → 经劫持 DNS 解析海外域名
// （内部走 sing-box DNS 分流 + 代理查询）→ 直拨海外 IP:443（流量被分流路由吸进
// TUN，能通即证明代理链路工作）→ 断开 → 校验网卡/路由/进程清理回滚。
// 仅用于验证，不影响正常 UI 使用。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func runTunSelfTest(a *App) int {
	tunVerbose = true
	fmt.Println("== KNcloud-WIN TUN (SSTap) self test ==")
	dumpRouteTable()

	// 全表条数基线（新版 API 口径）：旧版 IP Helper 看不见断开网卡上的路由，
	// 只查 8.8.8.8 会误报“已恢复”。停止后条数必须回到基线附近，否则就是僵尸路由泄漏。
	routeCount := func() int {
		out, err := runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Measure-Object).Count")
		n := -1
		_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
		if err != nil && n < 0 {
			return -1
		}
		return n
	}
	routesBefore := routeCount()
	fmt.Printf("[dump] IPv4 route rows (new API): %d\n", routesBefore)

	fail := 0

	// 注意：SimpleConnect 内部会拿 a.mu，这里不能再持锁调用（RWMutex 不可重入）
	started, err := a.SimpleConnect(true)
	if err != nil || !started {
		fmt.Printf("[FAIL] SimpleConnect(start): err=%v started=%v\n", err, started)
		return 1
	}
	fmt.Println("[ OK ] SimpleConnect(start)")

	a.mu.RLock()
	idx := a.tunIfaceIdx
	hostRouteN := len(a.tunHostRoutes)
	nativePath := a.nativeTunCmd != nil
	a.mu.RUnlock()
	fmt.Printf("[ OK ] tun iface index=%d, node host routes=%d\n", idx, hostRouteN)
	// 数据面有两条路径：原生 tun2socks 吃 "SSTAP 1"，Go/gvisor 吃常驻 "KNcloud-TAP"。
	// 按实际走的路径校验网卡名（此前硬编码 KNcloud-TAP，走原生路径时必误报）。
	wantAdapter := tunIfaceName
	pathName := "Go gvisor"
	if nativePath {
		wantAdapter = nativeSSTapIface
		pathName = "native tun2socks"
	}
	fmt.Printf("[info] data plane under test: %s (adapter %s)\n", pathName, wantAdapter)

	// 1) 网卡存在 + 系统去往海外的最优路由已指向 TUN 网卡
	if _, err := net.InterfaceByName(wantAdapter); err != nil {
		fmt.Printf("[FAIL] adapter %s: %v\n", wantAdapter, err)
		fail++
	} else {
		fmt.Printf("[ OK ] adapter %s present\n", wantAdapter)
	}
	// 1a) 去往海外的最优路由应指向 TUN 网卡。
	//     例外：DNS 服务器（1.1.1.1 / 8.8.8.8 等）按设计走物理直连 —— TUN 的 UDP
	//     经 tun2socks SOCKS UDP ASSOCIATE 转发有连接池上限，打满后会持续丢包，
	//     导致域名解析全失败。所以这里挑一个不是 DNS 的海外地址来验证。
	const probeIP = "9.9.9.10"
	r, ok := bestRouteForIPv4(net.ParseIP(probeIP), 0)
	if !ok || r.IfIndex != idx || r.Mask == 0 {
		fmt.Printf("[FAIL] best route to %s: ifIdx=%d gw=%v (want TUN ifIdx=%d, non-default prefix)\n",
			probeIP, r.IfIndex, dwordToIP(r.NextHop), idx)
		fail++
	} else {
		fmt.Printf("[ OK ] %s routed via TUN (ifIdx=%d gw=%v mask=%08x)\n", probeIP, r.IfIndex, dwordToIP(r.NextHop), r.Mask)
	}
	// 1b-2) DNS 服务器必须走物理直连（否则 UDP 池打满 -> DNS 全挂）
	dnsDirect := true
	for _, dnsIP := range []string{"1.1.1.1", "8.8.8.8", "223.5.5.5"} {
		if dr, dok := bestRouteForIPv4(net.ParseIP(dnsIP), 0); !dok || dr.IfIndex == idx {
			fmt.Printf("[FAIL] DNS %s not routed direct (ifIdx=%d)\n", dnsIP, dr.IfIndex)
			dnsDirect = false
			fail++
		}
	}
	if dnsDirect {
		fmt.Println("[ OK ] DNS servers routed direct (bypass TUN UDP pool)")
	}

	// 1b) IPv6 防泄漏：2000::/3 送进 TUN 网卡。
	// 仅 Go 路径适用：原生 tun2socks 只给网卡配 IPv4，没有 tunGateway6 这个
	// IPv6 地址，2000::/3 无处可指（写了也是无效路由），故跳过断言。
	if nativePath {
		fmt.Println("[skip] IPv6 split route: native path has no IPv6 on TAP adapter (not applicable)")
	} else {
		v6Out, v6Err := runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("if (Get-NetRoute -DestinationPrefix '2000::/3' -InterfaceIndex %d -ErrorAction SilentlyContinue) { 'OK' } else { 'MISSING' }", idx))
		if v6Err != nil || strings.Contains(string(v6Out), "MISSING") {
			fmt.Printf("[FAIL] IPv6 split route 2000::/3 via TUN: err=%v out=%s\n", v6Err, strings.TrimSpace(string(v6Out)))
			fail++
		} else {
			fmt.Printf("[ OK ] IPv6 split route 2000::/3 via TUN (leak protection on)\n")
		}
	}

	// 2) DNS 劫持链路：系统解析器 → 劫持 DNS → sing-box 分流 → 代理查询
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	ips, derr := net.DefaultResolver.LookupIPAddr(ctx, "www.google.com")
	cancel()
	if derr != nil || len(ips) == 0 {
		fmt.Printf("[FAIL] hijacked DNS resolve www.google.com: %v\n", derr)
		fail++
	} else {
		fmt.Printf("[ OK ] hijacked DNS resolved www.google.com -> %v\n", ips)

		// 3) 海外 TCP：直拨 google IP:443，流量经分流路由进 TUN → sing-box → 代理
		target := (&net.TCPAddr{IP: ips[0].IP, Port: 443}).String()
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, terr := d.Dial("tcp", target)
		if terr != nil {
			fmt.Printf("[FAIL] TCP %s: %v\n", target, terr)
			fail++
		} else {
			conn.Close()
			fmt.Printf("[ OK ] TCP %s connected via TUN->proxy\n", target)
		}
	}

	// 4) TUN 模式分流语义校验。
	//    TUN 开启后策略固定为「除局域网外全部走代理」，所以要验两件事：
	//      a) 国内站点也必须从代理节点出站 —— 用国内 IP 查询服务反查出口 IP；
	//      b) 局域网必须直连 —— 物理网关仍可直达。
	//    旧版这里只查路由表就打印「Xray rules send it direct」，从不观察实际出站，
	//    属于恒真的假断言；这里改为校验真实出口 IP。
	cnSet := parseCIDRList(cnRoutesTxt)
	inCN := func(ip net.IP) bool {
		for _, n := range cnSet {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}

	// 节点自身 IP：出口 IP 等于它即可确凿证明走了代理
	var nodeIP net.IP
	a.mu.RLock()
	for i := range a.nodes {
		if a.nodes[i].Active {
			if ips := lookupNodeIPv4sCached(a.nodes[i].Address); len(ips) > 0 {
				nodeIP = ips[0]
			}
			break
		}
	}
	a.mu.RUnlock()

	if exitIP := fetchExitIP(); exitIP != nil {
		switch {
		case nodeIP != nil && exitIP.Equal(nodeIP):
			fmt.Printf("[ OK ] CN site exits via proxy node (exit IP %s == node IP)\n", exitIP)
		case inCN(exitIP):
			fmt.Printf("[FAIL] TUN policy must proxy CN traffic, but exit IP %s is still inside CN ranges (went direct)\n", exitIP)
			fail++
		default:
			fmt.Printf("[ OK ] CN site exits via proxy node (exit IP %s outside CN ranges)\n", exitIP)
		}
	} else {
		fmt.Println("[warn] exit IP lookup failed; skipped CN-proxy assertion")
	}

	// 局域网直连：物理网卡仍在，私网地址不经代理
	if gw := physicalGateway(a); gw != nil {
		if c, err := net.DialTimeout("tcp", gw.String(), 3*time.Second); err == nil {
			c.Close()
			fmt.Printf("[ OK ] LAN gateway %s reachable directly (bypasses proxy)\n", gw)
		} else {
			fmt.Printf("[warn] LAN gateway %s not reachable: %v\n", gw, err)
		}
	}

	// 5) 断开 + 清理校验
	stopped, serr := a.SimpleConnect(false)
	if serr != nil || stopped {
		fmt.Printf("[FAIL] SimpleConnect(stop): err=%v stopped=%v\n", serr, stopped)
		fail++
	} else {
		fmt.Println("[ OK ] SimpleConnect(stop)")
	}
	// 网卡常驻保留是现行设计（下次秒开），停止后不断言消失；
	// 只要分流路由恢复 + 转发进程退出即算清理干净。
	if _, err := net.InterfaceByName(wantAdapter); err == nil {
		fmt.Printf("[ OK ] adapter %s kept resident by design\n", wantAdapter)
	} else {
		fmt.Printf("[ OK ] adapter %s removed\n", wantAdapter)
	}
	if r2, ok2 := bestRouteForIPv4(net.ParseIP(probeIP), 0); !ok2 || r2.IfIndex == idx {
		fmt.Printf("[FAIL] stale route to %s via ifIdx=%d after stop\n", probeIP, r2.IfIndex)
		fail++
	} else {
		fmt.Printf("[ OK ] routes restored (%s via ifIdx=%d gw=%v)\n", probeIP, r2.IfIndex, dwordToIP(r2.NextHop))
	}
	a.mu.RLock()
	singboxGone := a.tunCmd == nil && a.tunJob == 0 && a.tunIfaceIdx == 0 && len(a.tunHostRoutes) == 0 && len(a.tunSplitRoutes) == 0 && a.nativeTunCmd == nil
	a.mu.RUnlock()
	if !singboxGone {
		fmt.Printf("[FAIL] TUN state not fully cleaned\n")
		fail++
	} else {
		fmt.Println("[ OK ] TUN state fully cleaned")
	}

	// 6) 僵尸路由检查：停止后全表条数回到基线（±16 条容差给虚拟网卡自身直连路由）
	if routesBefore >= 0 {
		routesAfter := routeCount()
		fmt.Printf("[dump] IPv4 route rows after stop (new API): %d (baseline %d)\n", routesAfter, routesBefore)
		if routesAfter < 0 || routesAfter > routesBefore+16 {
			fmt.Printf("[FAIL] route table leaked: before=%d after=%d\n", routesBefore, routesAfter)
			fail++
		} else {
			fmt.Println("[ OK ] no route leak (table back to baseline)")
		}
	}

	fmt.Printf("== self test done: %s ==\n", map[bool]string{true: "PASS", false: "FAIL"}[fail == 0])
	if fail > 0 {
		return 1
	}
	return 0
}

// fetchExitIP 反查当前出口 IP。用国内托管的查询服务，这样返回的地址落在
// 中国网段就说明流量是直连出去的（没被代理），落在境外则说明走了代理节点。
func fetchExitIP() net.IP {
	client := &http.Client{Timeout: 8 * time.Second}
	for _, u := range []string{"https://ip.3322.net", "https://myip.ipip.net"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil {
			return ip
		}
	}
	return nil
}

// physicalGateway 找出物理网卡的默认网关（TUN 网卡上的默认路由要排除）。
// 用于验证「局域网直连」这条规则确实生效。
func physicalGateway(a *App) *net.TCPAddr {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	tunIdx := a.tunIfaceIdx
	a.mu.RUnlock()

	rows, err := getIpForwardTable()
	if err != nil {
		return nil
	}
	var best *net.TCPAddr
	var bestMetric uint32
	for _, r := range rows {
		if r.Mask != 0 || r.Dest != 0 || r.NextHop == 0 {
			continue // 只看 0.0.0.0/0
		}
		if tunIdx != 0 && r.IfIndex == tunIdx {
			continue // 跳过 TUN 网卡自己写入的默认路由
		}
		if best == nil || r.Metric1 < bestMetric {
			bestMetric = r.Metric1
			best = &net.TCPAddr{IP: dwordToIP(r.NextHop), Port: 80}
		}
	}
	return best
}

// dumpRouteTable 打印系统默认路由（旧 API 读取，验证字段语义正确）
func dumpRouteTable() {
	rows, err := getIpForwardTable()
	if err != nil {
		fmt.Printf("[dump] getIpForwardTable error: %v\n", err)
		return
	}
	fmt.Printf("[dump] %d IPv4 route rows\n", len(rows))
	for _, r := range rows {
		if r.Mask == 0 && r.Dest == 0 {
			fmt.Printf("[dump] default route: gw=%s ifIdx=%d metric=%d type=%d proto=%d\n",
				dwordToIP(r.NextHop), r.IfIndex, r.Metric1, r.Type, r.Proto)
		}
	}
	if br, ok := getBestRoute(net.ParseIP("8.8.8.8")); ok {
		fmt.Printf("[dump] GetBestRoute(8.8.8.8): gw=%s ifIdx=%d metric=%d type=%d\n",
			dwordToIP(br.NextHop), br.IfIndex, br.Metric1, br.Type)
	}
}

var _ = windows.AF_INET
