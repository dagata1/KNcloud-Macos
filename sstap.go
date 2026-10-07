package main

// SSTap 核心功能的 Go 重写（来源：D:\SSTap-beta 的 TAP.exe + rules/*.rules 分流方案）。
//
// SSTap 原实现：TAP 虚拟网卡 + 按 .rules 规则文件写路由表分流 + ss-local 隧道
// + privoxy（系统代理）+ unbound（DNS 分流防污染）。KNcloud-WIN 中的等价物：
//   - TAP 驱动        -> 常驻 wintun 虚拟网卡 KNcloud-TAP + gVisor 协议栈（tapstack.go / tapfwd.go）
//   - 路由表分流      -> tunroutes.go（期望表 + 差量同步；规则文件由本文件解析）
//   - ss-local 隧道   -> Xray 出站（真实节点协议）
//   - privoxy         -> Xray HTTP/SOCKS 入站 + Windows 系统代理
//   - unbound         -> 转发器 DNS 中继（223.5.5.5，绑定物理网卡）+ Xray 域名嗅探
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
