package main

// tunctl.go —— TUN 开关、换节点、换策略的编排（Go/gVisor 主路径 + 可选原生 badvpn）。
//
// 设计（对齐 SSTap）：
//   - TUN 是一个「接管开关」，与分流策略（绕过大陆 / 全局 / SSTap 规则文件）组合使用；
//   - 策略落在路由表上：默认路由进 TUN，「跳过」的网段（中国大陆 IP）写成物理网卡路由，
//     国内流量根本不进隧道；Xray 用同一策略兜底处理进了 TUN 的流量（域名规则）；
//   - 所有路由变化都是「期望表 vs 记账表」的差量（tunroutes.go），先加后删；
//   - 换节点只动节点 /32 与出站，分流路由、DNS 劫持、IPv6 防泄漏全程不动。

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (a *App) tunRouteOps() routeOps {
	if a.tunOps != nil {
		return a.tunOps
	}
	return winRouteOps{}
}

func (a *App) activeNodeLocked() *NodeItem {
	for i := range a.nodes {
		if a.nodes[i].Active {
			return &a.nodes[i]
		}
	}
	return nil
}

// nativeTunPreferred 原生 badvpn + SSTap TAP 引擎仅在显式开启时使用
// （KNCLOUD_NATIVE_TUN=1）。它依赖 SSTap 的 TAP 驱动、单线程，且会与 SSTap 本身冲突；
// 修好后的 gVisor 路径是默认引擎。
func nativeTunPreferred() bool { return os.Getenv("KNCLOUD_NATIVE_TUN") == "1" }

// tunNodeHops 预校验并解析节点：节点 IPv4 + 每个 IP 的物理出口。任何一步失败都在
// 拆除任何现网状态之前返回，调用方据此判定 errNodeRejected。
func tunNodeHops(node NodeItem, tunIdx uint32) ([]hopRoute, error) {
	ips := lookupNodeIPv4sCached(node.Address)
	if len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve a valid IPv4 address for node %s (DNS polluted or IPv6-only; IPv6-only nodes are not supported in TUN mode)", node.Address)
	}
	var hops []hopRoute
	for _, ip := range ips {
		if h, ok := physHopFor(ip, tunIdx); ok {
			hops = append(hops, hopRoute{IP: ip, Hop: h})
		}
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("no physical route to node %s (%v)", node.Address, ips)
	}
	return hops, nil
}

func tunDNSHops(list string, tunIdx uint32) []hopRoute {
	var out []hopRoute
	for _, ip := range dnsServerIPs(list) {
		if h, ok := physHopFor(ip, tunIdx); ok {
			out = append(out, hopRoute{IP: ip, Hop: h})
		}
	}
	return out
}

// tunPlanLocked 当前状态下的期望路由表。
func (a *App) tunPlanLocked(nodeHops []hopRoute, policy string) ([]routeEntry, tunPolicyShape, error) {
	gw := tunGateway
	hijack := true
	if a.nativeTunRunning() {
		gw, hijack = nativeSSTapRouterIP, false
	}
	return buildTunRoutePlan(tunRoutePlanInput{
		Policy:     policy,
		TunIdx:     a.tunIfaceIdx,
		TunGateway: ipToU32(net.ParseIP(gw)),
		HijackDNS:  hijack,
		NodeHops:   nodeHops,
		DNSHops:    tunDNSHops(a.settings.DnsServers, a.tunIfaceIdx),
		Phys:       a.tunPhys,
	})
}

// ------------------------- 转发运行时启停 -------------------------

// startTapForwarding 在常驻网卡上启动 gVisor 协议栈与转发协程（幂等）。
func (a *App) startTapForwarding() error {
	if a.tap != nil {
		return nil
	}
	dev := currentTunDevice()
	link := dev.NewLink()
	f, err := newTapForwarder(link, tapForwarderConfig{
		SocksAddr:   fmt.Sprintf("127.0.0.1:%d", a.settings.SocksPort),
		SocksUDP:    a.tunSocksUDPAddr(),
		DNSAddr:     tunDnsAddr,
		DNSUpstream: "223.5.5.5:53",
		BindIdx:     a.tunPhys.IfIndex,
	})
	if err != nil {
		dev.StopLink(link, time.Second)
		return err
	}
	a.tap = f
	return nil
}

// stopTapForwarding 停止协议栈与全部转发协程（网卡保留）。
// 先停链路读协程（最多等 1s），再关闭全部连接并 Destroy 协议栈。
func (a *App) stopTapForwarding() {
	f := a.tap
	if f == nil {
		return
	}
	a.tap = nil
	if !currentTunDevice().StopLink(f.linkEP, time.Second) {
		a.addLogInternal("warn", "TUN readLoop did not stop within 1s")
	}
	if !f.stop(2 * time.Second) {
		a.addLogInternal("warn", "TUN forwarder goroutines still draining after 2s")
	}
}

// tunUDPInboundTag TUN 专用的 UDP SOCKS 入站（不嗅探，见 buildCoreConfigJSON）
const tunUDPInboundTag = "tun-udp-in"

func (a *App) tunSocksUDPAddr() string {
	if a.tunUDPPort == 0 {
		return ""
	}
	return fmt.Sprintf("127.0.0.1:%d", a.tunUDPPort)
}

// pickFreeLoopbackPort 取一个 TCP 与 UDP 都空闲的回环端口（失败返回 0：UDP 退回 socks-in）
func pickFreeLoopbackPort() int {
	for i := 0; i < 5; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		l.Close()
		if err == nil {
			u.Close()
			return port
		}
	}
	return 0
}

// ------------------------- 对外开关 -------------------------

// SimpleConnect 简易/仪表盘的 TUN 开关。
//
// TUN 与分流策略组合生效：绕过大陆（大陆网段走物理网卡，不进隧道）、全局、
// SSTap 规则文件。策略为「全局直连」时开 TUN 没有意义，临时改为全局并在关闭时恢复。
func (a *App) SimpleConnect(start bool) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if start {
		err := a.tunStartLocked()
		a.savePersisted()
		tray.requestRebuild()
		return a.tunRunning, err
	}
	a.tunSoftStopLocked()
	a.savePersisted()
	tray.requestRebuild()
	return a.tunRunning, nil
}

func (a *App) tunStartLocked() error {
	if a.tunRunning {
		return nil
	}
	if !isElevated() {
		a.addLogInternal("error", "TUN mode requires administrator privileges")
		return fmt.Errorf("TUN mode requires administrator privileges")
	}
	node := a.activeNodeLocked()
	if node == nil {
		return fmt.Errorf("no node selected")
	}
	t0 := time.Now()

	// 0) 预校验：策略可用、节点可解析、物理出口存在 —— 失败时什么都没动。
	policy := a.routingMode
	forced := false
	if policy == "direct" || policy == "" {
		policy, forced = "global", true
	}
	if _, err := tunPolicyShapeFor(policy); err != nil {
		return err
	}
	dev := currentTunDevice()
	staleIdx := dev.CachedIfIdx()
	hops, err := tunNodeHops(*node, staleIdx)
	if err != nil {
		a.addLogInternal("error", "TUN: "+err.Error())
		return err
	}
	phys, ok := physHopFor(net.ParseIP("223.5.5.5"), staleIdx)
	if !ok {
		phys = hops[0].Hop
	}
	ifc, err := net.InterfaceByIndex(int(phys.IfIndex))
	if err != nil || ifc.Name == "" {
		return fmt.Errorf("cannot determine physical interface (ifIdx=%d): %v", phys.IfIndex, err)
	}
	sweepStaleBypassRoutes()

	// 1) 常驻虚拟网卡 + metric/MTU/地址
	native := false
	var ifIdx uint32
	if nativeTunPreferred() {
		if nerr := a.startNativeTun(*node); nerr == nil {
			native, ifIdx = true, a.tunIfaceIdx
		} else {
			a.addLogInternal("info", fmt.Sprintf("Native tun2socks engine unavailable (%v), using built-in gVisor stack", nerr))
		}
	}
	if !native {
		ifIdx, err = dev.Open()
		if err != nil {
			a.addLogInternal("error", fmt.Sprintf("TUN: adapter error: %v", err))
			return fmt.Errorf("adapter error: %v", err)
		}
		if err := dev.Configure(ifIdx); err != nil {
			a.addLogInternal("error", fmt.Sprintf("TUN: configure adapter failed: %v", err))
			return err
		}
	}

	// 2) Xray 以 TUN 配置（出站绑物理网卡、无 mux、只嗅探 http/tls）启动/重启
	prevMode := a.routingMode
	if forced {
		a.prevRoutingMode = prevMode
		a.routingMode = policy
		a.addLogInternal("info", fmt.Sprintf("TUN: policy %s → %s while TUN is on (restored when TUN stops)", prevMode, policy))
	}
	wasCore := a.coreRunning
	a.tunEgressIface = ifc.Name
	a.tunUDPPort = pickFreeLoopbackPort()
	if err := a.startCoreLocked(); err != nil {
		a.addLogInternal("error", fmt.Sprintf("TUN: start core failed: %v", err))
		a.tunEgressIface = ""
		a.tunUDPPort = 0
		if forced {
			a.routingMode, a.prevRoutingMode = prevMode, ""
		}
		a.stopNativeTun()
		a.coreRunning = false
		if wasCore {
			if rerr := a.startCoreLocked(); rerr == nil {
				a.coreRunning = true
			}
		}
		return fmt.Errorf("start core failed: %v", err)
	}
	a.coreRunning = true

	// 3) 转发 → 网卡 DNS → 路由（先 /32 防回环，最后才是吸流量的默认路由）
	a.tunIfaceIdx = ifIdx
	a.tunPhys = phys
	if a.tunRt == nil {
		a.tunRt = newTunRouteState()
	}
	fail := func(err error) error {
		a.addLogInternal("error", "TUN: "+err.Error())
		a.tunRunning = true // 让软停走完整清理（含恢复内核配置）
		a.tunSoftStopLocked()
		return err
	}
	if !native {
		if err := a.startTapForwarding(); err != nil {
			return fail(fmt.Errorf("forwarding stack failed: %v", err))
		}
		if err := setTapAdapterDNS(ifIdx); err != nil {
			return fail(err)
		}
		a.tapDnsHijacked = true
	} else {
		clearTapAdapterDNS(ifIdx)
	}
	desired, shape, err := a.tunPlanLocked(hops, policy)
	if err != nil {
		return fail(err)
	}
	tr := time.Now()
	added, _, err := a.tunRt.sync(a.tunRouteOps(), desired)
	if err != nil {
		return fail(fmt.Errorf("routing setup failed: %v", err))
	}
	routeDur := time.Since(tr)
	if shape.Defaults && !native {
		if err := addTunIPv6Route(ifIdx); err == nil {
			a.tunV6 = true
		} else {
			a.addLogInternal("warn", fmt.Sprintf("TUN: IPv6 leak-protection route not installed: %v", err))
		}
	}
	a.tunRunning = true
	flushDnsClientCache()
	engine := "gVisor (" + dev.Name() + ")"
	if native {
		engine = "native tun2socks (SSTAP 1)"
	}
	a.addLogInternal("info", fmt.Sprintf("TUN ready | engine %s | policy %s | %d routes (%d bypass) in %s | egress %s | total %s | node: %s",
		engine, policy, added, a.tunRt.count("bypass"), routeDur.Round(time.Millisecond), ifc.Name, time.Since(t0).Round(time.Millisecond), node.Name))
	return nil
}

// tunSoftStopLocked TUN 软停止：停转发 + 撤路由与 DNS 劫持（常驻网卡保留），
// 内核恢复为普通代理配置，被临时改写的策略复原。
func (a *App) tunSoftStopLocked() {
	wasRunning := a.tunRunning
	a.stopNativeTun()
	a.stopTapForwarding()
	a.removeTapRouting()
	a.tunIfaceIdx = 0
	a.tunRunning = false
	if a.prevRoutingMode != "" {
		a.routingMode = a.prevRoutingMode
		a.prevRoutingMode = ""
	}
	if a.tunEgressIface != "" {
		a.tunEgressIface = ""
		a.tunUDPPort = 0
		if a.coreRunning {
			if err := a.startCoreLocked(); err != nil {
				a.coreRunning = false
				a.addLogInternal("error", fmt.Sprintf("Restart core after TUN stop failed: %v", err))
			}
		}
	}
	if wasRunning {
		a.addLogInternal("info", "TUN stopped, all traffic back to direct (adapter kept installed)")
	}
}

// removeTapRouting 撤除 TUN 写入的全部路由与 DNS 劫持（网卡保留）。
// 不依赖 tunRunning：失败路径的半装状态同样按账清理。
func (a *App) removeTapRouting() {
	failed := 0
	if a.tunRt != nil {
		removed, f := a.tunRt.clear(a.tunRouteOps())
		failed = f
		if removed > 0 {
			a.addLogInternal("info", fmt.Sprintf("Removed %d TUN routes", removed))
		}
		if failed > 0 {
			a.addLogInternal("warn", fmt.Sprintf("%d TUN routes could not be removed, will retry", failed))
		}
	}
	idx := a.tunIfaceIdx
	if idx == 0 {
		return
	}
	if failed > 0 {
		if err := removeTapRoutesBulk(idx); err != nil {
			a.addLogInternal("warn", fmt.Sprintf("Failed to sweep TUN routes on ifIdx=%d: %v", idx, err))
		}
	}
	// 只要网卡上可能残留劫持 DNS 就清（Go 路径设过，或上一轮运行留下的）
	clearTapAdapterDNS(idx)
	a.tapDnsHijacked = false
	removeTunIPv6RouteFast(idx)
	a.tunV6 = false
}

// setTapAdapterDNS 网卡 DNS 指向劫持地址（netsh 写错参数时退出码仍为 0，必须回读校验）。
func setTapAdapterDNS(ifIdx uint32) error {
	if adapterHasDns(ifIdx, tunDnsAddr) {
		return nil
	}
	out, err := runHidden("netsh", "interface", "ipv4", "set", "dnsservers",
		fmt.Sprintf("name=%d", ifIdx), "source=static", fmt.Sprintf("address=%s", tunDnsAddr), "validate=no")
	if err != nil {
		return fmt.Errorf("failed to configure adapter DNS: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !adapterHasDns(ifIdx, tunDnsAddr) {
		return fmt.Errorf("adapter DNS not applied (want %s on ifIdx=%d): %s", tunDnsAddr, ifIdx, strings.TrimSpace(string(out)))
	}
	return nil
}

// ------------------------- 换节点 -------------------------

// tunSwitchDeps 换节点流程里与路由无关的步骤（单测注入 fake 以校验顺序）。
type tunSwitchDeps struct {
	commitOutbound    func() error // 内核换上新节点（热切换或整体重启）
	restartForwarding func() error // 重启转发：断开 TUN 上的存量连接
	flushDNS          func()
}

// runTunNodeSwitch 换节点的路由编排：
//
//  1. 加新节点 /32（此刻新旧 /32 并存，任何节点的连接都不会进 TUN）
//  2. 内核换上新节点
//  3. 删旧节点 /32
//  4. 重启转发（存量长连接断开，重连即走新节点）
//  5. 清 DNS 缓存
//
// 分流默认路由、绕过网段、DNS 劫持、IPv6 路由都在 desired 里原样保留，不会被删。
// 第 1/2 步失败时恢复原状并返回 errNodeRejected（隧道与旧节点照常工作）。
func runTunNodeSwitch(st *tunRouteState, ops routeOps, desired []routeEntry, deps tunSwitchDeps) error {
	before := map[routeKey]bool{}
	for k := range st.installed {
		before[k] = true
	}
	undo := func() {
		var keep []routeEntry
		for _, r := range st.entries("") {
			if before[r.routeKey] {
				keep = append(keep, r)
			}
		}
		st.deleteStale(ops, keep)
	}
	if _, err := st.addMissing(ops, desired); err != nil {
		undo()
		return fmt.Errorf("%w: %v", errNodeRejected, err)
	}
	if err := deps.commitOutbound(); err != nil {
		if errors.Is(err, errNodeRejected) {
			undo()
			return err
		}
		return err
	}
	_, derr := st.deleteStale(ops, desired)
	if err := deps.restartForwarding(); err != nil {
		return fmt.Errorf("restart TUN forwarding: %w", err)
	}
	deps.flushDNS()
	if derr != nil {
		return fmt.Errorf("node switched but stale route cleanup failed: %w", derr)
	}
	return nil
}

// tunHardSwitchLocked TUN 运行中换节点。返回 errNodeRejected（可能被包装）表示
// 新节点在动任何现网状态前被拒绝/已完整回滚：隧道仍在旧节点上正常工作，调用方不要软停。
func (a *App) tunHardSwitchLocked(node NodeItem) error {
	if !a.tunRunning || a.tunIfaceIdx == 0 {
		return fmt.Errorf("TUN is not running")
	}
	t0 := time.Now()
	hops, err := tunNodeHops(node, a.tunIfaceIdx)
	if err != nil {
		return fmt.Errorf("%w: %v", errNodeRejected, err)
	}
	desired, _, err := a.tunPlanLocked(hops, a.routingMode)
	if err != nil {
		return fmt.Errorf("%w: %v", errNodeRejected, err)
	}
	var prepared *preparedOutbound
	if a.coreRunning {
		p, err := a.prepareProxyOutboundLocked(node)
		switch {
		case err == nil:
			prepared = p
		case errors.Is(err, errHotSwapUnavailable):
		default:
			return fmt.Errorf("%w: %v", errNodeRejected, err)
		}
	}
	deps := tunSwitchDeps{
		commitOutbound: func() error {
			err := errHotSwapUnavailable
			if prepared != nil {
				err = a.commitProxyOutboundLocked(prepared)
			}
			switch {
			case err == nil:
				a.coreNodeID = node.ID
				return nil
			case errors.Is(err, errHotSwapUnavailable):
				if err := a.restartCoreLocked(); err != nil {
					return err
				}
				return nil
			default:
				// 新出站装不上、旧出站已放回：内核仍在旧节点上
				return fmt.Errorf("%w: switch outbound: %v", errNodeRejected, err)
			}
		},
		restartForwarding: func() error {
			if a.nativeTunRunning() {
				return nil // badvpn 只连本机 SOCKS，出站已换，旧连接已被 conntrack 切断
			}
			a.stopTapForwarding()
			return a.startTapForwarding()
		},
		flushDNS: flushDnsClientCache,
	}
	err = runTunNodeSwitch(a.tunRt, a.tunRouteOps(), desired, deps)
	if err != nil {
		return err
	}
	a.addLogInternal("info", fmt.Sprintf("TUN node switched in %s | %d node route(s) | split routes untouched | node: %s (%s:%d)",
		time.Since(t0).Round(time.Millisecond), len(hops), node.Name, node.Address, node.Port))
	return nil
}

// ------------------------- 换策略 -------------------------

// tunSetPolicyLocked TUN 运行中切换分流策略：路由差量（先加后删）+ Xray 规则热替换。
// 失败（规则文件不可用、路由写不进）时策略与路由保持原样。
func (a *App) tunSetPolicyLocked(mode string) error {
	node := a.activeNodeLocked()
	if node == nil {
		return fmt.Errorf("no node selected")
	}
	hops, err := tunNodeHops(*node, a.tunIfaceIdx)
	if err != nil {
		return err
	}
	desired, shape, err := a.tunPlanLocked(hops, mode)
	if err != nil {
		return err
	}
	ops := a.tunRouteOps()
	before := map[routeKey]bool{}
	for k := range a.tunRt.installed {
		before[k] = true
	}
	t0 := time.Now()
	added, err := a.tunRt.addMissing(ops, desired)
	if err != nil {
		var keep []routeEntry
		for _, r := range a.tunRt.entries("") {
			if before[r.routeKey] {
				keep = append(keep, r)
			}
		}
		a.tunRt.deleteStale(ops, keep)
		return err
	}
	a.routingMode = mode
	a.prevRoutingMode = ""
	if a.coreRunning {
		err := a.applyRoutingLocked()
		if err != nil && errors.Is(err, errHotSwapUnavailable) {
			err = a.startCoreLocked()
		}
		if err != nil {
			a.coreRunning = false
			a.addLogInternal("error", fmt.Sprintf("TUN: core failed after policy change, stopping TUN: %v", err))
			a.tunSoftStopLocked()
			return err
		}
	}
	removed, derr := a.tunRt.deleteStale(ops, desired)
	if shape.Defaults && !a.tunV6 && !a.nativeTunRunning() {
		if addTunIPv6Route(a.tunIfaceIdx) == nil {
			a.tunV6 = true
		}
	} else if !shape.Defaults && a.tunV6 {
		removeTunIPv6RouteFast(a.tunIfaceIdx)
		a.tunV6 = false
	}
	a.addLogInternal("info", fmt.Sprintf("TUN policy → %s in %s | +%d / -%d routes | %d bypass routes now",
		mode, time.Since(t0).Round(time.Millisecond), added, removed, a.tunRt.count("bypass")))
	return derr
}

// ------------------------- 残留清扫 -------------------------

var (
	procGetIpForwardTable2 = iphlpapi.NewProc("GetIpForwardTable2")
)

// listRoutes2 枚举系统 IPv4 路由（新版 API，断开网卡上的路由也可见）。
func listRoutes2() ([]mibIPForwardRow2, error) {
	var tbl uintptr
	r, _, _ := procGetIpForwardTable2.Call(windows.AF_INET, uintptr(unsafe.Pointer(&tbl)))
	if r != 0 {
		return nil, windows.Errno(r)
	}
	defer procFreeMibTable.Call(tbl)
	n := *(*uint32)(unsafe.Pointer(tbl))
	const rowSize = unsafe.Sizeof(mibIPForwardRow2{})
	base := tbl + 8 // NumEntries 后按 8 字节对齐
	rows := make([]mibIPForwardRow2, n)
	for i := uint32(0); i < n; i++ {
		rows[i] = *(*mibIPForwardRow2)(unsafe.Pointer(base + uintptr(i)*rowSize))
	}
	return rows, nil
}

func row2ToEntry(row mibIPForwardRow2) (routeEntry, bool) {
	if *(*uint16)(unsafe.Pointer(&row.DestinationPrefix[0])) != windows.AF_INET {
		return routeEntry{}, false
	}
	var dest, hop [4]byte
	copy(dest[:], row.DestinationPrefix[4:8])
	copy(hop[:], row.NextHop[4:8])
	return routeEntry{
		routeKey: routeKey{Dest: ipToU32(dest[:]), Bits: row.DestinationPrefix[28], NextHop: ipToU32(hop[:]), IfIndex: row.InterfaceIndex},
		Metric:   row.Metric,
	}, true
}

// sweepStaleBypassRoutes 清掉上次异常退出残留在物理网卡上的绕过路由。
// TUN 网卡上的路由随适配器消失，但物理网卡上的几千条 CN 网段会一直留到重启；
// 物理网关一旦变化（换 Wi-Fi）它们就指向错误网关。只删同时满足「我们的 metric 标记、
// NETMGMT 来源、前缀属于内置 CN/私网集合」的路由，不会误删用户自己的静态路由。
func sweepStaleBypassRoutes() int {
	rows, err := listRoutes2()
	if err != nil {
		return 0
	}
	ours := map[[2]uint32]bool{}
	for _, c := range cnCIDRs() {
		r := newRoute(c, 0, 0, 0, "")
		ours[[2]uint32{r.Dest, uint32(r.Bits)}] = true
	}
	for _, s := range privateBypassCIDRs {
		_, c, _ := net.ParseCIDR(s)
		r := newRoute(*c, 0, 0, 0, "")
		ours[[2]uint32{r.Dest, uint32(r.Bits)}] = true
	}
	n := 0
	for _, row := range rows {
		if row.Protocol != ipProtoNetMgmt || (row.Metric != bypassRouteMetric && row.Metric != privateRouteMetric) {
			continue
		}
		e, ok := row2ToEntry(row)
		if !ok || !ours[[2]uint32{e.Dest, uint32(e.Bits)}] {
			continue
		}
		if (winRouteOps{}).DeleteRoute(e) == nil {
			n++
		}
	}
	return n
}
