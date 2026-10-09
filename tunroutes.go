package main

// tunroutes.go —— TUN 路由的「期望集合 + 差量同步」引擎（SSTap 式规则分流）。
//
// SSTap 的做法：TAP 网卡上挂默认路由（0/1 + 128/1），规则文件里「跳过」的 CIDR
// （如 Skip-all-China-IP）写成物理网卡网关路由 —— 最长前缀匹配让这些目的地址
// 根本不进隧道，国内流量原生速度直连。
//
// 本文件把 TUN 写入系统的全部 IPv4 路由（默认路由、DNS 劫持 /32、节点 /32、
// DNS 服务器 /32、绕过大陆的几千条 CN 网段）统一成一张「期望表」，与已安装的
// 记账表做差量：先加新增、再删多余。换节点只动节点 /32，换模式只动策略网段，
// 分流默认路由与 DNS 劫持全程不动 —— 不存在直连泄漏窗口。
//
// 写路由直接走 IP Helper API（CreateIpForwardEntry2 / DeleteIpForwardEntry2），
// 进程内一次系统调用一条，数千条在百毫秒级完成；绝不逐条 fork netsh。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// routeKey 唯一标识一条 IPv4 路由（地址均为主机序数值：1.2.3.4 → 0x01020304）。
type routeKey struct {
	Dest    uint32
	Bits    uint8
	NextHop uint32
	IfIndex uint32
}

// routeEntry 一条要写入/已写入的 IPv4 路由。Metric 是「路由 metric」，
// 系统生效值 = Metric + 网卡 interface metric（CreateIpForwardEntry2 语义）。
type routeEntry struct {
	routeKey
	Metric uint32
	// Kind 仅用于日志与统计：host（节点/DNS /32）、split（进 TUN）、bypass（走物理网卡）
	Kind string
}

func (r routeEntry) String() string {
	return fmt.Sprintf("%s/%d via %s if=%d m=%d", u32ToIP(r.Dest), r.Bits, u32ToIP(r.NextHop), r.IfIndex, r.Metric)
}

func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func u32ToIP(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func newRoute(n net.IPNet, nextHop uint32, ifIdx, metric uint32, kind string) routeEntry {
	ones, _ := n.Mask.Size()
	return routeEntry{
		routeKey: routeKey{Dest: ipToU32(n.IP.Mask(n.Mask)), Bits: uint8(ones), NextHop: nextHop, IfIndex: ifIdx},
		Metric:   metric,
		Kind:     kind,
	}
}

var (
	errRouteExists   = errors.New("route already exists")
	errRouteNotFound = errors.New("route not found")
)

// routeOps 系统路由表操作（Windows 实现走 IP Helper；单测用 fake 记录调用顺序）。
type routeOps interface {
	AddRoute(r routeEntry) error    // 已存在返回 errRouteExists
	DeleteRoute(r routeEntry) error // 不存在返回 errRouteNotFound
}

// tunRouteState 已安装路由的记账。任何一条加成功（或已存在）的路由都立即入账，
// 失败路径不会丢账：软停时按账逐条删，保证不留残留。
type tunRouteState struct {
	installed map[routeKey]routeEntry
}

func newTunRouteState() *tunRouteState {
	return &tunRouteState{installed: map[routeKey]routeEntry{}}
}

func (s *tunRouteState) count(kind string) int {
	if s == nil {
		return 0
	}
	n := 0
	for _, r := range s.installed {
		if kind == "" || r.Kind == kind {
			n++
		}
	}
	return n
}

func (s *tunRouteState) has(k routeKey) bool {
	if s == nil {
		return false
	}
	_, ok := s.installed[k]
	return ok
}

// entries 返回已安装路由（按 kind 过滤，空串表示全部），顺序稳定。
func (s *tunRouteState) entries(kind string) []routeEntry {
	if s == nil {
		return nil
	}
	var out []routeEntry
	for _, r := range s.installed {
		if kind == "" || r.Kind == kind {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Dest != b.Dest {
			return a.Dest < b.Dest
		}
		if a.Bits != b.Bits {
			return a.Bits < b.Bits
		}
		return a.IfIndex < b.IfIndex
	})
	return out
}

// addMissing 按 desired 的顺序补齐缺失的路由。能加的都加，返回首个错误。
func (s *tunRouteState) addMissing(ops routeOps, desired []routeEntry) (added int, err error) {
	for _, r := range desired {
		if _, ok := s.installed[r.routeKey]; ok {
			continue
		}
		e := ops.AddRoute(r)
		if e == nil || errors.Is(e, errRouteExists) {
			s.installed[r.routeKey] = r
			added++
			continue
		}
		if err == nil {
			err = fmt.Errorf("add route %s: %w", r, e)
		}
	}
	return added, err
}

// deleteStale 删除已安装但不在 desired 里的路由；删不掉的留在账上。
func (s *tunRouteState) deleteStale(ops routeOps, desired []routeEntry) (removed int, err error) {
	want := make(map[routeKey]bool, len(desired))
	for _, r := range desired {
		want[r.routeKey] = true
	}
	for _, r := range s.entries("") {
		if want[r.routeKey] {
			continue
		}
		e := ops.DeleteRoute(r)
		if e == nil || errors.Is(e, errRouteNotFound) {
			delete(s.installed, r.routeKey)
			removed++
			continue
		}
		if err == nil {
			err = fmt.Errorf("delete route %s: %w", r, e)
		}
	}
	return removed, err
}

// sync 把系统路由同步到 desired：先补齐缺失的（make-before-break），再删多余的。
// 不会因错误中断：账目始终与系统实际一致。
func (s *tunRouteState) sync(ops routeOps, desired []routeEntry) (added, removed int, err error) {
	added, err = s.addMissing(ops, desired)
	removed, derr := s.deleteStale(ops, desired)
	if err == nil {
		err = derr
	}
	return added, removed, err
}

// clear 删除全部已安装路由；删不掉的留在账上（返回失败条数），便于下次重试。
func (s *tunRouteState) clear(ops routeOps) (removed, failed int) {
	if s == nil {
		return 0, 0
	}
	for _, r := range s.entries("") {
		e := ops.DeleteRoute(r)
		if e == nil || errors.Is(e, errRouteNotFound) {
			delete(s.installed, r.routeKey)
			removed++
		} else {
			failed++
		}
	}
	return removed, failed
}

// ------------------------- 期望路由表计算 -------------------------

// physHop 物理网卡出口（网卡索引 + 下一跳；on-link/PPPoE 时下一跳为 0）。
type physHop struct {
	IfIndex uint32
	NextHop uint32
}

// tunRoutePlanInput 计算期望路由表所需的全部输入（纯数据，便于单测）。
type tunRoutePlanInput struct {
	Policy     string
	TunIdx     uint32
	TunGateway uint32
	HijackDNS  bool       // Go 路径：198.18.0.2/32 进 TUN，由转发器的 DNS 中继应答
	NodeHops   []hopRoute // 节点服务器 IP 及其物理出口
	DNSHops    []hopRoute // 配置的 DNS 服务器 IP 及其物理出口
	Phys       physHop    // 默认物理出口（绕过网段用）
}

type hopRoute struct {
	IP  net.IP
	Hop physHop
}

const (
	hostRouteMetric  = 1 // 节点 / DNS /32：最长前缀已经保证优先，metric 取最小
	splitRouteMetric = 5 // 进 TUN 的分流路由
	// 绕过网段的 metric 兼作「本程序写入」的标记（异常退出后据此清扫残留，见
	// sweepStaleBypassRoutes）；前缀比 0/1 长，生效与否不取决于 metric。
	bypassRouteMetric = 37
	// 私网网段兜底走物理网卡：metric 很高，绝不抢已有的同前缀路由（VPN 等）
	privateRouteMetric = 4037
)

// privateBypassCIDRs 非直连子网的私网/CGNAT 目的地址：走物理网卡而不是进 TUN。
// TUN 默认路由 0/1 会覆盖它们；Xray 对私网走 freedom，而 freedom 的 UDP 不受
// sockopt.interface 约束，进 TUN 会形成回环 —— 在路由表层直接放行最稳。
var privateBypassCIDRs = []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"}

// tunPolicyShape 描述一种策略在路由表上的形状。
type tunPolicyShape struct {
	Defaults bool        // 是否挂 0/1 + 128/1（以及 IPv6 2000::/3）进 TUN
	Tun      []net.IPNet // 额外进 TUN 的网段（仅代理列表内 IP 的策略）
	Bypass   []net.IPNet // 走物理网卡的网段（跳过列表内 IP 的策略）
}

var cnCIDRsCache []net.IPNet

// cnCIDRs 内置中国大陆 IPv4 网段（合并相邻/包含网段后的最小 CIDR 集合）。
func cnCIDRs() []net.IPNet {
	if cnCIDRsCache == nil {
		cnCIDRsCache = aggregateCIDRs(parseCIDRList(cnRoutesTxt))
	}
	return cnCIDRsCache
}

// aggregateCIDRs 合并重叠与相邻网段并重新切成最少的 CIDR。
func aggregateCIDRs(in []net.IPNet) []net.IPNet {
	if len(in) == 0 {
		return nil
	}
	blocks := make([]ipRange, 0, len(in))
	for _, c := range in {
		blocks = append(blocks, cidrToRange(c))
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].s < blocks[j].s })
	merged := []ipRange{blocks[0]}
	for _, b := range blocks[1:] {
		last := &merged[len(merged)-1]
		if b.s <= last.e+1 {
			if b.e > last.e {
				last.e = b.e
			}
			continue
		}
		merged = append(merged, b)
	}
	var out []net.IPNet
	for _, m := range merged {
		out = append(out, rangeToCIDRs(m.s, m.e)...)
	}
	return out
}

// tunPolicyShapeFor 把分流策略翻译成路由表形状（SSTap 规则语义）：
//
//	global        默认路由进 TUN，其余交给 Xray（局域网直连）
//	bypass-cn     默认路由进 TUN + 中国大陆网段走物理网卡（= SSTap Skip-all-China-IP）
//	proxy-cn      仅中国大陆网段进 TUN（= SSTap China-IP-only）
//	sstap:<file>  规则文件 skip=1：默认路由进 TUN + 列表网段走物理网卡；
//	              skip=0：仅列表网段进 TUN
func tunPolicyShapeFor(policy string) (tunPolicyShape, error) {
	switch {
	case policy == "global":
		return tunPolicyShape{Defaults: true}, nil
	case policy == "bypass-cn":
		return tunPolicyShape{Defaults: true, Bypass: cnCIDRs()}, nil
	case policy == "proxy-cn":
		return tunPolicyShape{Tun: cnCIDRs()}, nil
	case strings.HasPrefix(policy, "sstap:"):
		r, err := parseSstapRuleFile(strings.TrimPrefix(policy, "sstap:"))
		if err != nil {
			return tunPolicyShape{}, err
		}
		if r.Skip {
			return tunPolicyShape{Defaults: true, Bypass: aggregateCIDRs(r.CIDRs)}, nil
		}
		return tunPolicyShape{Tun: aggregateCIDRs(r.CIDRs)}, nil
	}
	return tunPolicyShape{}, fmt.Errorf("routing mode %q is not supported in TUN mode", policy)
}

// buildTunRoutePlan 计算期望路由表。顺序有意义（sync 按此顺序添加）：
// 先 /32 防回环（节点、DNS），再绕过网段，最后才是进 TUN 的分流路由 ——
// 任何时刻都不会出现「流量已被吸进 TUN、但节点 /32 还没铺好」的回环窗口。
func buildTunRoutePlan(in tunRoutePlanInput) ([]routeEntry, tunPolicyShape, error) {
	shape, err := tunPolicyShapeFor(in.Policy)
	if err != nil {
		return nil, shape, err
	}
	if in.TunIdx == 0 {
		return nil, shape, fmt.Errorf("TUN interface index unknown")
	}
	var out []routeEntry
	seen := map[routeKey]bool{}
	add := func(r routeEntry) {
		if seen[r.routeKey] {
			return
		}
		seen[r.routeKey] = true
		out = append(out, r)
	}
	host := func(h hopRoute) {
		if h.IP.To4() == nil || h.Hop.IfIndex == 0 || h.Hop.IfIndex == in.TunIdx {
			return
		}
		add(newRoute(net.IPNet{IP: h.IP.To4(), Mask: net.CIDRMask(32, 32)}, h.Hop.NextHop, h.Hop.IfIndex, hostRouteMetric, "host"))
	}
	for _, h := range in.NodeHops {
		host(h)
	}
	for _, h := range in.DNSHops {
		host(h)
	}
	if in.Phys.IfIndex != 0 && in.Phys.IfIndex != in.TunIdx {
		for _, c := range shape.Bypass {
			add(newRoute(c, in.Phys.NextHop, in.Phys.IfIndex, bypassRouteMetric, "bypass"))
		}
		if shape.Defaults {
			for _, s := range privateBypassCIDRs {
				_, n, _ := net.ParseCIDR(s)
				add(newRoute(*n, in.Phys.NextHop, in.Phys.IfIndex, privateRouteMetric, "bypass"))
			}
		}
	} else if len(shape.Bypass) > 0 {
		return nil, shape, fmt.Errorf("physical gateway unknown, cannot install %d bypass routes", len(shape.Bypass))
	}
	if in.HijackDNS {
		_, n, _ := net.ParseCIDR(tunDnsAddr + "/32")
		add(newRoute(*n, in.TunGateway, in.TunIdx, 1, "split"))
	}
	for _, c := range shape.Tun {
		add(newRoute(c, in.TunGateway, in.TunIdx, splitRouteMetric, "split"))
	}
	if shape.Defaults {
		for _, s := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			_, n, _ := net.ParseCIDR(s)
			add(newRoute(*n, in.TunGateway, in.TunIdx, splitRouteMetric, "split"))
		}
	}
	return out, shape, nil
}

// ------------------------- Windows：IP Helper v2 -------------------------

// dnsServerIPs 解析设置里的 DNS 服务器列表（仅 IPv4）。
func dnsServerIPs(list string) []net.IP {
	var out []net.IP
	for _, s := range strings.Split(list, ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && ip.To4() != nil {
			out = append(out, ip.To4())
		}
	}
	return out
}
