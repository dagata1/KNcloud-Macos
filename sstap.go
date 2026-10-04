package main

// SSTap 核心功能的 Go 重写（来源：D:\SSTap-beta 的 TAP.exe + rules/*.rules 分流方案）。
//
// SSTap 原实现：TAP 虚拟网卡 + 按 .rules 规则文件写路由表分流 + ss-local 隧道
// + privoxy（系统代理）+ unbound（DNS 分流防污染）。KNcloud-WIN 中的等价物：
//   - TAP 驱动        -> sing-box + wintun 虚拟网卡（tun.go）
//   - 路由表分流      -> applySstapRouting（本文件的策略路由计算）
//   - ss-local 隧道   -> sing-box 出站（真实节点协议）
//   - privoxy         -> Xray HTTP/SOCKS 入站 + Windows 系统代理
//   - unbound         -> sing-box DNS（geosite-cn 分流 + 公共 DNS 兜底）
//
// SSTap 的 .rules 文件格式（rules/Skip-all-China-IP.rules 等）：
//   首行元数据：#<规则名>,<描述>,<skip 标志>,...
//   之后每行一条 CIDR（如 1.0.1.0/24）
// skip 标志 = 1：跳过列表内 IP，代理其余流量（Skip-all-China-IP.rules）
// skip 标志 = 0：仅代理列表内 IP，其余直连（China-IP-only.rules）

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type sstapRule struct {
	Name  string
	Desc  string
	Skip  bool // true=跳过列表内 IP（代理其余）；false=仅代理列表内 IP
	CIDRs []net.IPNet
}

// parseSstapRuleFile 解析 SSTap .rules 规则文件
func parseSstapRuleFile(path string) (*sstapRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &sstapRule{Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))}
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i == 0 && strings.HasPrefix(line, "#") {
			fields := strings.Split(strings.TrimPrefix(line, "#"), ",")
			if len(fields) > 0 {
				r.Name = strings.TrimSpace(fields[0])
			}
			if len(fields) > 1 {
				r.Desc = strings.TrimSpace(fields[1])
			}
			// 第 3 个字段为 skip 标志（对照两份内置规则：Skip=1，China-IP-only=0）
			if len(fields) > 2 {
				r.Skip = strings.TrimSpace(fields[2]) == "1"
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(line); err == nil && ipnet.IP.To4() != nil {
			r.CIDRs = append(r.CIDRs, *ipnet)
		}
	}
	if len(r.CIDRs) == 0 {
		return nil, fmt.Errorf("no CIDR entries in %s", path)
	}
	return r, nil
}

// parseCIDRList 把多行 CIDR 文本解析为 IPv4 路由条目（忽略 IPv6 与非法行）
func parseCIDRList(txt string) []net.IPNet {
	var out []net.IPNet
	for _, line := range strings.Split(txt, "\n") {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(line))
		if err != nil || ipnet.IP.To4() == nil {
			continue
		}
		out = append(out, *ipnet)
	}
	return out
}

type ipRange struct{ s, e uint64 }

func cidrToRange(n net.IPNet) ipRange {
	ones, _ := n.Mask.Size()
	// 注意：这里必须用大端序数值（与 ipToDword 的小端 DWORD 不同，那是路由 API 的内存表示）
	start := uint64(binary.BigEndian.Uint32(n.IP.To4()))
	return ipRange{start, start + (uint64(1) << (32 - ones)) - 1}
}

// complementCIDRs 求补集：整个 IPv4 空间减去 cidrs（skip 类规则的「代理其余流量」）
func complementCIDRs(cidrs []net.IPNet) []net.IPNet {
	const full = uint64(1) << 32
	blocks := make([]ipRange, 0, len(cidrs))
	for _, c := range cidrs {
		blocks = append(blocks, cidrToRange(c))
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].s < blocks[j].s })

	merged := blocks[:0]
	for _, b := range blocks {
		if n := len(merged); n > 0 && b.s <= merged[n-1].e+1 {
			if b.e > merged[n-1].e {
				merged[n-1].e = b.e
			}
			continue
		}
		merged = append(merged, b)
	}

	var out []net.IPNet
	cur := uint64(0)
	for _, b := range merged {
		if b.s > cur {
			out = append(out, rangeToCIDRs(cur, b.s-1)...)
		}
		if b.e+1 > cur {
			cur = b.e + 1
		}
	}
	if cur < full {
		out = append(out, rangeToCIDRs(cur, full-1)...)
	}
	return out
}

// sstapTunRoutesFast 返回「全量流量进 TUN、分流交给 Xray」所需的最小路由集合：
// 只有两条默认路由（0.0.0.0/1 + 128.0.0.0/1，合起来即 0.0.0.0/0）。
//
// 为什么要这样：bypass-cn 在路由表层需要写入「非中国大陆」的补集，高达 12825 条
// CIDR。写入要 1.5 秒、删除要几十秒，而且每条都要触发一次系统路由变更通知，
// 导致 TUN 开关极慢、关闭窗口时 UI 被锁死。而这些分流规则 Xray 里本来就有一份
// （core.go：geoip:cn / geosite:cn → direct，其余 → proxy），路由表等于把同一套
// 策略实现了两遍，还容易与内核策略不一致。
//
// 改为只送默认路由后，所有流量进入 TUN 再由 Xray 按同一套规则分流，结果等价；
// 代价是国内流量也会多走一次用户态协议栈（CPU 略高、延迟略增）。
//
// 仅对内置四种策略走快路径；sstap:<file> 自定义 .rules 是任意 CIDR 集合，
// 无法用 Xray 规则表达，仍需路由表层分流（保持原行为）。
func sstapTunRoutesFast(policy string) ([]net.IPNet, bool) {
	switch policy {
	case "bypass-cn", "global", "direct", "proxy-cn":
		_, a, _ := net.ParseCIDR("0.0.0.0/1")
		_, b, _ := net.ParseCIDR("128.0.0.0/1")
		return []net.IPNet{*a, *b}, true
	}
	return nil, false
}

// sstapPolicyRoutes 计算指定分流策略下需要指向虚拟网卡网关的 CIDR 列表。
// 策略（与 SSTap rules 的对应关系）：
//   bypass-cn       代理中国大陆以外流量（= Skip-all-China-IP.rules）
//   global          代理全部流量
//   proxy-cn        仅代理中国大陆 IP（= China-IP-only.rules）
//   sstap:<file>    按指定 .rules 规则文件分流
func sstapPolicyRoutes(policy string) ([]net.IPNet, error) {
	switch {
	case policy == "global":
		_, a, _ := net.ParseCIDR("0.0.0.0/1")
		_, b, _ := net.ParseCIDR("128.0.0.0/1")
		return []net.IPNet{*a, *b}, nil
	case policy == "proxy-cn":
		return parseCIDRList(cnRoutesTxt), nil
	case strings.HasPrefix(policy, "sstap:"):
		r, err := parseSstapRuleFile(strings.TrimPrefix(policy, "sstap:"))
		if err != nil {
			return nil, err
		}
		if r.Skip {
			return complementCIDRs(r.CIDRs), nil
		}
		return r.CIDRs, nil
	default: // bypass-cn
		cn := parseCIDRList(cnRoutesTxt)
		cn = append(cn, parseCIDRList(strings.Join(reservedCIDRs, "\n"))...)
		return complementCIDRs(cn), nil
	}
}
