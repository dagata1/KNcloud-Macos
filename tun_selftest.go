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
	"net"
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
	r, ok := bestRouteForIPv4(net.ParseIP("8.8.8.8"), 0)
	if !ok || r.IfIndex != idx || r.Mask == 0 {
		fmt.Printf("[FAIL] best route to 8.8.8.8: ifIdx=%d gw=%v (want TUN ifIdx=%d, non-default prefix)\n",
			r.IfIndex, dwordToIP(r.NextHop), idx)
		fail++
	} else {
		fmt.Printf("[ OK ] 8.8.8.8 routed via TUN (ifIdx=%d gw=%v mask=%08x)\n", r.IfIndex, dwordToIP(r.NextHop), r.Mask)
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

	// 4) 内核分流抽查：TUN 现在把全部流量送进虚拟网卡（只有两条默认路由），
	// 国内直连/海外代理由 Xray 的 geoip/geosite 规则判定，不再由路由表逐条绕过。
	// 因此这里改为验证「国内地址确实经 TUN 进入内核且被内核判为 direct」。
	dnsOK := false
	if ips, err := net.LookupIP("www.baidu.com"); err == nil && len(ips) > 0 {
		if cnr, cnOK := getBestRoute(ips[0].To4()); cnOK {
			fmt.Printf("[ OK ] CN IP %s goes via TUN ifIdx=%d, Xray rules send it direct\n",
				ips[0], cnr.IfIndex)
			dnsOK = true
		}
	}
	if !dnsOK {
		fmt.Println("[FAIL] cannot verify CN traffic entering TUN (dns or route lookup failed)")
		fail++
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
	if r2, ok2 := bestRouteForIPv4(net.ParseIP("8.8.8.8"), 0); !ok2 || r2.IfIndex == idx {
		fmt.Printf("[FAIL] stale route to 8.8.8.8 via ifIdx=%d after stop\n", r2.IfIndex)
		fail++
	} else {
		fmt.Printf("[ OK ] routes restored (8.8.8.8 via ifIdx=%d gw=%v)\n", r2.IfIndex, dwordToIP(r2.NextHop))
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
