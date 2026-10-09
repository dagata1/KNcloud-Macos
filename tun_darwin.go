//go:build darwin

package main

// tun_darwin.go —— TUN 编排（tunctl.go，与 Windows 共用）在 macOS 上的系统层实现：
// 路由查询读内核路由表（PF_ROUTE，无需 root），路由/DNS 写入交给特权助手。
//
// 与 Windows 的差异：
//   - 没有 WFP：DNS 防泄漏靠「系统 DNS 指向 198.18.0.2 + 该地址 /32 进 TUN」，
//     IPv6 泄漏靠 2000::/3 进 TUN（与 Windows 相同的路由级防护）；
//   - BSD 路由没有 metric：最长前缀优先，0/1+128/1 天然压过默认路由；
//   - 原生 badvpn/SSTap 引擎只有 Windows 有，macOS 恒为 gVisor。

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"os/exec"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// darwinTunIfIdx 当前 utun 的接口索引（未打开为 0）。
var darwinTunIfIdx atomic.Uint32

// nativeSSTapRouterIP 仅 Windows 原生引擎使用；macOS 上 nativeTunRunning 恒为 false。
const nativeSSTapRouterIP = "10.198.75.61"

var errNativeTunUnavailable = errors.New("native SSTap tun2socks engine is Windows-only")

func (a *App) startNativeTun(node NodeItem) error { return errNativeTunUnavailable }
func (a *App) stopNativeTun()                     {}
func (a *App) nativeTunRunning() bool             { return false }
func nativeTunIfaceIndex() (uint32, error)        { return 0, errNativeTunUnavailable }

// hiddenProc macOS 没有控制台窗口问题。
func hiddenProc() *syscall.SysProcAttr { return nil }

// prepareTunPrivileges 开 TUN 前（不持有 a.mu）确保特权助手已运行：首次会弹出管理员授权框。
func prepareTunPrivileges() error { return tunHelper.ensure() }

// isElevated macOS 上表示「特权助手已就绪」。
func isElevated() bool { return tunHelper.connected() }

// flushDnsClientCache 清系统 DNS 缓存（mDNSResponder 需要 root，助手在时交给助手）。
func flushDnsClientCache() {
	if tunHelper.connected() {
		if _, err := tunHelper.do(helperReq{Op: "flush_dns"}); err == nil {
			return
		}
	}
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
}

func ifaceNameByIndex(idx uint32) string {
	if ifc, err := net.InterfaceByIndex(int(idx)); err == nil {
		return ifc.Name
	}
	return ""
}

// setTapAdapterDNS 把各网络服务的 DNS 指向劫持地址（由 TUN 内的 DNS 中继应答）。
func setTapAdapterDNS(ifIdx uint32) error {
	if _, err := tunHelper.do(helperReq{Op: "dns_set", DNS: []string{tunDnsAddr}}); err != nil {
		return fmt.Errorf("failed to configure system DNS: %v", err)
	}
	return nil
}

// clearTapAdapterDNS 还原被改写的系统 DNS。
func clearTapAdapterDNS(ifIdx uint32) bool {
	if !tunHelper.connected() {
		return true
	}
	_, err := tunHelper.do(helperReq{Op: "dns_restore"})
	return err == nil
}

func adapterHasDns(ifIdx uint32, want string) bool {
	if !tunHelper.connected() {
		return false
	}
	resp, err := tunHelper.do(helperReq{Op: "dns_get"})
	return err == nil && resp.Bool
}

// removeTapRoutesBulk 让助手撤掉它在该网卡上加过的全部路由。
func removeTapRoutesBulk(ifIdx uint32) error {
	if !tunHelper.connected() {
		return nil
	}
	_, err := tunHelper.do(helperReq{Op: "route_clear", Iface: ifaceNameByIndex(ifIdx)})
	return err
}

// addTunIPv6Route IPv6 全局单播 2000::/3 进 utun，堵住 IPv6 泄漏。
func addTunIPv6Route(ifIdx uint32) error {
	name := ifaceNameByIndex(ifIdx)
	if name == "" {
		return fmt.Errorf("utun ifIdx=%d not found", ifIdx)
	}
	resp, err := tunHelper.do(helperReq{Op: "route_add", Dst: "2000::/3", Iface: name, V6: true})
	if err != nil {
		return err
	}
	if resp.Code == "exists" {
		return fmt.Errorf("another 2000::/3 route already exists (another VPN?)")
	}
	return nil
}

func removeTunIPv6RouteFast(ifIdx uint32) {
	if !tunHelper.connected() {
		return
	}
	if name := ifaceNameByIndex(ifIdx); name != "" {
		_, _ = tunHelper.do(helperReq{Op: "route_del", Dst: "2000::/3", Iface: name, V6: true})
	}
}

// scopedPhysDefaultReq 物理网卡的作用域默认路由（route add -net 0.0.0.0/0 <gw> -ifscope en0）。
//
// 为什么需要：TUN 挂上 0/1 + 128/1 后，绑定物理网卡（IP_BOUND_IF）的 socket —— DNS 中继、
// Xray 的 sockopt.interface 出站 —— 在 XNU 里做作用域路由查找：系统只有一条不带作用域的
// default（主网卡），更具体的 0/1、128/1 又在 utun 上，查找结果与绑定接口不符，connect 直接
// 报 ENETUNREACH（network is unreachable）。系统偶尔会给非主网卡装 IFSCOPE 默认路由，
// 但主网卡通常没有。补一条 en0 作用域的默认路由，只影响绑定了 en0 的 socket，不改普通流量走向。
func scopedPhysDefaultReq(op string, phys physHop) (helperReq, bool) {
	name := ifaceNameByIndex(phys.IfIndex)
	if name == "" {
		return helperReq{}, false
	}
	req := helperReq{Op: op, Dst: "0.0.0.0/0", Scope: name}
	if phys.NextHop == 0 {
		req.Iface = name
	} else {
		req.Gateway = u32ToIP(phys.NextHop).String()
	}
	return req, true
}

// addScopedPhysDefault 装上物理网卡的作用域默认路由（已存在则沿用，不记账也不会删除）。
func addScopedPhysDefault(phys physHop) error {
	req, ok := scopedPhysDefaultReq("route_add", phys)
	if !ok {
		return fmt.Errorf("physical interface %d not found", phys.IfIndex)
	}
	_, err := tunHelper.do(req)
	return err
}

// removeScopedPhysDefault 撤销 addScopedPhysDefault 加的路由（助手只删自己加过的）。
func removeScopedPhysDefault(phys physHop) {
	if phys.IfIndex == 0 || !tunHelper.connected() {
		return
	}
	if req, ok := scopedPhysDefaultReq("route_del", phys); ok {
		_, _ = tunHelper.do(req)
	}
}

// sweepStaleBypassRoutes Windows 用来清理异常退出残留；macOS 上物理网卡路由由助手记账，
// 主程序退出（含崩溃）后助手自行撤销，utun 上的路由随网卡消失。
func sweepStaleBypassRoutes() int { return 0 }

// ------------------------- 路由写入（经助手） -------------------------

type darwinRouteOps struct{}

func defaultRouteOps() routeOps { return darwinRouteOps{} }

func helperRouteReq(op string, r routeEntry) (helperReq, error) {
	req := helperReq{Op: op, Dst: fmt.Sprintf("%s/%d", u32ToIP(r.Dest), r.Bits)}
	tun := darwinTunIfIdx.Load()
	if r.IfIndex != 0 && (r.IfIndex == tun || r.NextHop == 0) {
		// 进 utun 的路由、以及 on-link（PPPoE 等无网关）物理出口：按接口写
		req.Iface = ifaceNameByIndex(r.IfIndex)
		if req.Iface == "" {
			return req, fmt.Errorf("interface index %d not found", r.IfIndex)
		}
		return req, nil
	}
	req.Gateway = u32ToIP(r.NextHop).String()
	return req, nil
}

func (darwinRouteOps) AddRoute(r routeEntry) error {
	req, err := helperRouteReq("route_add", r)
	if err != nil {
		return err
	}
	resp, err := tunHelper.do(req)
	if err != nil {
		return err
	}
	if resp.Code == "exists" {
		return errRouteExists
	}
	return nil
}

func (darwinRouteOps) DeleteRoute(r routeEntry) error {
	req, err := helperRouteReq("route_del", r)
	if err != nil {
		return err
	}
	resp, err := tunHelper.do(req)
	if err != nil {
		return err
	}
	if resp.Code == "notfound" {
		return errRouteNotFound
	}
	return nil
}

// ------------------------- 路由查询（内核路由表） -------------------------

type darwinRoute struct {
	Dest    uint32
	Bits    int
	NextHop uint32 // 0 = on-link
	IfIndex uint32
	Scoped  bool // RTF_IFSCOPE：某接口专属的路由（非主路由）
}

// darwinIPv4Routes 读取内核 IPv4 路由表（NET_RT_DUMP，普通权限即可）。
func darwinIPv4Routes() ([]darwinRoute, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var out []darwinRoute
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
			continue
		}
		if len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		r := darwinRoute{Dest: ipToU32(net.IP(dst.IP[:])), IfIndex: uint32(rm.Index), Scoped: rm.Flags&unix.RTF_IFSCOPE != 0}
		switch {
		case rm.Flags&unix.RTF_HOST != 0:
			r.Bits = 32
		default:
			if mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); ok {
				r.Bits = bits.OnesCount32(ipToU32(net.IP(mask.IP[:])))
			} else if r.Dest == 0 {
				r.Bits = 0
			} else {
				r.Bits = 32
			}
		}
		if gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr); ok && rm.Flags&unix.RTF_GATEWAY != 0 {
			r.NextHop = ipToU32(net.IP(gw.IP[:]))
		}
		out = append(out, r)
	}
	return out, nil
}

// bestDarwinRoute 最长前缀匹配，跳过 exclude（TUN）与回环接口；同前缀优先非 IFSCOPE 的主路由。
func bestDarwinRoute(rows []darwinRoute, dst net.IP, exclude uint32, isLoopback func(uint32) bool) (darwinRoute, bool) {
	d := ipToU32(dst)
	var best darwinRoute
	found := false
	for _, r := range rows {
		if r.IfIndex == 0 || r.IfIndex == exclude || isLoopback(r.IfIndex) {
			continue
		}
		mask := uint32(0)
		if r.Bits > 0 {
			mask = ^uint32(0) << (32 - r.Bits)
		}
		if d&mask != r.Dest&mask {
			continue
		}
		better := !found || r.Bits > best.Bits || (r.Bits == best.Bits && best.Scoped && !r.Scoped)
		if better {
			best, found = r, true
		}
	}
	return best, found
}

func isLoopbackIfIndex(idx uint32) bool {
	ifc, err := net.InterfaceByIndex(int(idx))
	return err == nil && ifc.Flags&net.FlagLoopback != 0
}

// physHopFor 去往 ip 的物理出口（排除 TUN 与回环）。TUN 运行中也能返回物理出口。
func physHopFor(ip net.IP, tunIdx uint32) (physHop, bool) {
	if ip.To4() == nil {
		return physHop{}, false
	}
	rows, err := darwinIPv4Routes()
	if err != nil {
		return physHop{}, false
	}
	exclude := tunIdx
	if exclude == 0 {
		exclude = darwinTunIfIdx.Load()
	}
	r, ok := bestDarwinRoute(rows, ip, exclude, isLoopbackIfIndex)
	if !ok || r.IfIndex == darwinTunIfIdx.Load() {
		return physHop{}, false
	}
	return physHop{IfIndex: r.IfIndex, NextHop: r.NextHop}, true
}

// bindToIfaceControl 把 socket 绑定到指定网卡（IP_BOUND_IF），DNS 中继据此绕开 TUN 直连。
func bindToIfaceControl(ifIdx uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if len(network) > 0 && network[len(network)-1] == '6' {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(ifIdx))
				return
			}
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(ifIdx))
		})
		if err != nil {
			return err
		}
		return serr
	}
}
