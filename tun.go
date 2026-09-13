package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed cores/sing-box.exe
var singBoxBin []byte

// wintunDLL 是 sing-box TUN 入站创建虚拟网卡所必需的驱动 DLL（amd64，匹配内嵌的
// sing-box.exe）。来自官方发行包 wintun-0.14.1.zip，未做任何修改；
// 许可见 cores/wintun-LICENSE.txt —— 允许随「仅通过其 API 使用它」的软件一同分发。
//
//go:embed cores/wintun.dll
var wintunDLL []byte

//go:embed geo/cn-routes.txt
var cnRoutesTxt string

//go:embed geo/geosite-cn.srs
var geositeCnSrs []byte

const (
	tunLogTag      = "TUN"
	createNoWindow = 0x08000000

	// SSTap 方案核心参数（复刻 SSTap-beta 的 TAP 分流机制）
	tunIfaceName = "KNcloud-TAP"          // 固定虚拟网卡名（对应 SSTAP 1）
	tunGateway   = "172.19.0.1"           // 虚拟网卡网关地址（/30）
	tunDnsAddr   = "198.18.0.2"           // 写入虚拟网卡的系统 DNS，端口 53 被 sing-box 劫持
	tunMetric    = 1                      // 虚拟网卡接口 metric（对应 SSTap 抢占 DNS 优先级）
	routeMetric  = 5                      // 分流路由 metric
	tunGateway6  = "fdfe:dcba:9876::1"    // 虚拟网卡 IPv6 地址（/126），配合 2000::/3 分流路由堵 IPv6 泄漏
)

var (
	iphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestRoute         = iphlpapi.NewProc("GetBestRoute")
	procGetIpForwardTable    = iphlpapi.NewProc("GetIpForwardTable")
	procCreateIpForwardEntry = iphlpapi.NewProc("CreateIpForwardEntry")
	procDeleteIpForwardEntry = iphlpapi.NewProc("DeleteIpForwardEntry")
)

// 保留网段：永不写入虚拟网卡（私有/链路本地/组播等，保持系统直连行为）
var reservedCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}

// ensureSingBoxBin 将内嵌的 sing-box.exe 释放到用户配置目录，返回可执行文件路径。
func ensureSingBoxBin() (string, error) {
	dir, err := appConfigDir()
	if err != nil {
		return "", err
	}
	exePath := filepath.Join(dir, "sing-box.exe")
	if st, err := os.Stat(exePath); err == nil && st.Size() > 1024*1024 {
		return exePath, nil
	}
	if err := os.WriteFile(exePath, singBoxBin, 0755); err != nil {
		return "", err
	}
	return exePath, nil
}

// ensureWintunDLL 把内嵌的 wintun.dll 释放到 sing-box.exe 同目录，返回其路径。
//
// sing-box 的 TUN 入站靠 wintun.dll 创建虚拟网卡，缺了会以
// "configure tun interface: The system cannot find the file specified" 失败
// （Windows 那句报错不会点名是哪个文件，很容易误判成权限问题）。
//
// 放在 sing-box.exe 旁边即可被命中：Windows 默认 DLL 搜索顺序里，
// 可执行文件所在目录优先级最高，不需要动 System32 或 PATH。
func ensureWintunDLL(dir string) (string, error) {
	dllPath := filepath.Join(dir, "wintun.dll")
	if st, err := os.Stat(dllPath); err == nil && st.Size() == int64(len(wintunDLL)) {
		return dllPath, nil
	}
	if err := os.WriteFile(dllPath, wintunDLL, 0644); err != nil {
		return "", err
	}
	return dllPath, nil
}

// isElevated 当前进程是否以管理员权限运行（TUN 模式必需）
func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	var elevation uint32
	var retLen uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &retLen); err != nil {
		return false
	}
	return elevation != 0
}

// buildTunConfigJSON 生成 sing-box 配置（SSTap 方案）：
//   - TUN 入站不做 auto_route，默认路由完全不碰 —— 稳定性的根本来源
//   - DNS 分流：国内域名 -> 119.29.29.29（直连），其余 -> 8.8.8.8（经代理，等价 SSTap 的 unbound+china-list）
//   - geosite-cn.srs 用于 DNS 域名分流（等价 SSTap unbound 的 accelerated-domains.china.conf）
//
// bindIface 为物理出口网卡名：出站显式绑定到它，避免分流路由铺好后 sing-box 的
// auto_detect_interface 把出站（尤其是直连 DNS 查询）判到 TUN 网卡上、又灌回 tun-in，
// 造成 "DNS query loopback in transport[...]" 死循环。传空串表示不绑定（保持旧行为）。
func buildTunConfigJSON(node NodeItem, srsPath, bindIface string) (string, error) {
	proxyOut, err := nodeToSingBoxOutbound(node, bindIface)
	if err != nil {
		return "", err
	}

	directOut := map[string]interface{}{"type": "direct", "tag": "direct"}
	if bindIface != "" {
		directOut["bind_interface"] = bindIface
	}

	cfg := map[string]interface{}{
		// info 级别会输出 "router: updated default interface ..." 与 DNS 路由决策，
		// 是排查 TUN 分流问题最关键的线索（warn 级别会把这些全部丢掉）。
		"log": map[string]interface{}{"level": "info"},
		"dns": map[string]interface{}{
			"strategy": "ipv4_only",
			"servers": []map[string]interface{}{
				{"tag": "dns-cn", "address": "udp://119.29.29.29", "detour": "direct"},
				{"tag": "dns-fw", "address": "tcp://8.8.8.8", "detour": "proxy"},
			},
			"rules": []map[string]interface{}{
				// 节点服务器域名必须直连 DNS 解析，否则解析服务器地址要走代理 -> 死锁
				{"domain": []string{strings.ToLower(node.Address)}, "server": "dns-cn"},
				{"rule_set": []string{"geosite-cn"}, "server": "dns-cn"},
			},
			"final": "dns-fw",
		},
		"inbounds": []map[string]interface{}{{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": tunIfaceName,
			// v4 + v6 双栈地址：v6 地址存在才能把 2000::/3 写进该网卡堵 v6 泄漏
			// （分流路由只覆盖 IPv4，宿主机若有原生 IPv6，所有 v6 流量都会绕过 TUN 直连出网）
			"address":      []string{tunGateway + "/30", tunGateway6 + "/126"},
			"mtu":          9000,
			"auto_route":   false, // 核心：不劫持默认路由，由本进程手动写入分流路由
			"strict_route": false,
			"stack":        "mixed",
		}},
		"outbounds": []map[string]interface{}{
			proxyOut,
			{"type": "dns", "tag": "dns-out"},
			directOut,
		},
		"route": map[string]interface{}{
			"rules": []map[string]interface{}{
				{"port": 53, "outbound": "dns-out"},
				{"ip_is_private": true, "outbound": "direct"},
			},
			"rule_set": []map[string]interface{}{{
				"type": "local", "tag": "geosite-cn", "format": "binary", "path": srsPath,
			}},
			"final":                 "proxy",
			"auto_detect_interface": true,
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// nodeToSingBoxOutbound 将节点转换为 sing-box 出站配置。
// bindIface 非空时把出站显式绑定到物理网卡，防止节点连接被自己的分流路由吸回 TUN。
func nodeToSingBoxOutbound(node NodeItem, bindIface string) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"tag":         "proxy",
		"server":      node.Address,
		"server_port": node.Port,
	}
	if bindIface != "" {
		out["bind_interface"] = bindIface
	}

	tlsObj := func() map[string]interface{} {
		if node.Security != "tls" && node.Security != "reality" {
			return nil
		}
		t := map[string]interface{}{
			"enabled":     true,
			"server_name": firstNonEmpty(node.SNI, node.Address),
			"utls":        map[string]interface{}{"enabled": true, "fingerprint": firstNonEmpty(node.FP, "chrome")},
		}
		if node.Security == "reality" {
			t["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": node.PBK,
				"short_id":   node.SID,
			}
		}
		return t
	}()

	transport := func() map[string]interface{} {
		switch node.Network {
		case "ws":
			tr := map[string]interface{}{"type": "ws", "path": firstNonEmpty(node.Path, "/")}
			if node.HostName != "" {
				tr["headers"] = map[string]interface{}{"Host": node.HostName}
			}
			return tr
		case "grpc":
			return map[string]interface{}{"type": "grpc", "service_name": node.ServiceName}
		case "httpupgrade":
			return map[string]interface{}{"type": "httpupgrade", "path": firstNonEmpty(node.Path, "/"), "host": node.HostName}
		}
		return nil
	}()

	switch node.Protocol {
	case "VLESS":
		out["type"] = "vless"
		out["uuid"] = node.UUID
		if node.Flow != "" {
			out["flow"] = node.Flow
		}
	case "VMess":
		out["type"] = "vmess"
		out["uuid"] = node.UUID
		out["security"] = "auto"
		out["alter_id"] = node.AlterID
	case "Trojan":
		out["type"] = "trojan"
		out["password"] = node.UUID
	case "Shadowsocks":
		method := node.Method
		password := node.UUID
		if method == "" && strings.Contains(node.UUID, ":") {
			parts := strings.SplitN(node.UUID, ":", 2)
			method, password = parts[0], parts[1]
		}
		if method == "" {
			return nil, fmt.Errorf("Shadowsocks node missing cipher method")
		}
		out["type"] = "shadowsocks"
		out["method"] = method
		out["password"] = password
	case "Hysteria2":
		out["type"] = "hysteria2"
		out["password"] = node.UUID
	default:
		return nil, fmt.Errorf("TUN mode does not support protocol: %s", node.Protocol)
	}

	if tlsObj != nil {
		out["tls"] = tlsObj
	}
	if transport != nil {
		out["transport"] = transport
	}
	return out, nil
}

// ------------------------- 路由引擎（复刻 SSTap 的静态分流路由） -------------------------
//
// 使用旧版 IP Helper API（GetBestRoute / GetIpForwardTable / CreateIpForwardEntry /
// DeleteIpForwardEntry）：MIB_IPFORWARDROW 是纯 14-DWORD 结构，无对齐与布局歧义
// （x/sys 的 MIB_IPFORWARD_ROW2 布局与系统实测不符——实测每字段偏移 +4，读写皆错）。
// IP 地址以网络序存储于 DWORD：字段值 == binary.BigEndian.Uint32(ip)。

// mibIPForwardRow 对应 C 的 MIB_IPFORWARDROW（route.exe 同款）
type mibIPForwardRow struct {
	Dest, Mask, Policy, NextHop, IfIndex        uint32
	Type, Proto, Age, NextHopAS                 uint32
	Metric1, Metric2, Metric3, Metric4, Metric5 uint32
}

const (
	ipRouteTypeDirect   = 3 // on-link
	ipRouteTypeIndirect = 4 // 经网关
	ipProtoNetMgmt      = 3 // MIB_IPPROTO_NETMGMT：由网络管理实体（我们）写入
)

// ipToDword 将 IPv4 转为 MIB_IPFORWARDROW 字段的 DWORD。
// API 要求内存中为网络序字节（172.16.0.1 → AC 10 00 01），
// 小端机器上该 DWORD 的 Go 数值等于按 LittleEndian 读网络字节序切片。
func ipToDword(ip net.IP) uint32 {
	if v4 := ip.To4(); v4 != nil {
		return binary.LittleEndian.Uint32(v4)
	}
	return 0
}

// dwordToIP 将 MIB_IPFORWARDROW 字段 DWORD 还原为 IPv4（ipToDword 的逆变换）
func dwordToIP(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// getIpForwardTable 枚举系统 IPv4 路由表（调用方缓冲区版，无封送歧义）
func getIpForwardTable() ([]mibIPForwardRow, error) {
	size := uint32(0)
	ret, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 && ret != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER（首次探测的正常返回）
		return nil, syscall.Errno(ret)
	}
	buf := make([]byte, size)
	ret, _, _ = procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		return nil, syscall.Errno(ret)
	}
	if size < 4 {
		return nil, nil
	}
	rowSize := uint32(unsafe.Sizeof(mibIPForwardRow{}))
	n := binary.LittleEndian.Uint32(buf[0:4])
	if max := (size - 4) / rowSize; n > max {
		n = max
	}
	rows := make([]mibIPForwardRow, n)
	for i := uint32(0); i < n; i++ {
		copy((*[56]byte)(unsafe.Pointer(&rows[i]))[:], buf[4+i*rowSize:4+(i+1)*rowSize])
	}
	return rows, nil
}

// getBestRoute 查询系统去往 dst 的真实最优路由（GetBestRoute，排除逻辑由调用方处理）
func getBestRoute(dst net.IP) (mibIPForwardRow, bool) {
	var row mibIPForwardRow
	ret, _, _ := procGetBestRoute.Call(uintptr(ipToDword(dst)), 0, uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return row, false
	}
	return row, true
}

// addRouteRow 通过 CreateIpForwardEntry 写入一条路由
func addRouteRow(row *mibIPForwardRow) error {
	row.Policy = 0
	row.Proto = ipProtoNetMgmt
	row.Age = 0
	row.NextHopAS = 0
	row.Metric2, row.Metric3, row.Metric4, row.Metric5 = 0, 0, 0, 0
	ret, _, _ := procCreateIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

// interfaceMetric4 读取网卡的 IPv4 interface metric（即 netsh 里的自动跃点）。
//
// 关键坑：Vista 之后旧版路由 API 的 MIB_IPFORWARDROW.Metric1 语义变为
// 「接口 metric + 路由 metric」的合成值（route.exe 的 "metric 1" 落库后
// 实际是 ifaceMetric+1），CreateIpForwardEntry 传入小于接口 metric 的值
// 会被 ERROR_INVALID_PARAMETER 拒绝。所以所有写路由的地方都必须把
// 目标 metric 叠加在本接口的 interface metric 之上。
func interfaceMetric4(ifIdx uint32) uint32 {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: ifIdx}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return 0
	}
	return row.Metric
}

// addRoute2 便捷封装：目的 CIDR 经指定网卡/网关写入路由。
// metric 参数为「路由 metric」，叠加在网卡 interface metric 之上（见 interfaceMetric4）。
func addRoute2(ifIdx uint32, dst net.IPNet, nextHop net.IP, metric uint32) error {
	row := mibIPForwardRow{
		Dest:    ipToDword(dst.IP),
		Mask:    ipToDword(net.IP(dst.Mask)),
		NextHop: ipToDword(nextHop),
		IfIndex: ifIdx,
		Metric1: interfaceMetric4(ifIdx) + metric,
	}
	if row.NextHop == 0 {
		row.Type = ipRouteTypeDirect
	} else {
		row.Type = ipRouteTypeIndirect
	}
	return addRouteRow(&row)
}

// deleteRouteRow 删除一条路由（按 Dest/Mask/Policy/NextHop/IfIndex 匹配）
func deleteRouteRow(row *mibIPForwardRow) error {
	ret, _, _ := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

// deleteRoutesOnInterface 删除该网卡上的全部 IPv4 路由（虚拟网卡销毁时系统也会自动回收，此处是主动清理）
func deleteRoutesOnInterface(ifIdx uint32) int {
	rows, err := getIpForwardTable()
	if err != nil {
		return 0
	}
	n := 0
	for _, r := range rows {
		if r.IfIndex != ifIdx {
			continue
		}
		row := r
		if deleteRouteRow(&row) == nil {
			n++
		}
	}
	return n
}

// bestRouteFromRows 在路由表行中查找去往 dst 的最优 IPv4 路由：
// 最长前缀优先，前缀相同取 Metric1 最小；跳过回环与被排除的接口（通常是 TUN 自己）。
// NextHop 为 0.0.0.0 的 on-link 路由（PPPoE 等场景）同样有效。
func bestRouteFromRows(rows []mibIPForwardRow, dst net.IP, excludeIfIdx uint32) (mibIPForwardRow, bool) {
	d := ipToDword(dst)
	if d == 0 && dst.To4() == nil {
		return mibIPForwardRow{}, false
	}
	best := mibIPForwardRow{}
	found := false
	for _, r := range rows {
		if r.IfIndex == excludeIfIdx || r.IfIndex == 1 {
			continue
		}
		if d&r.Mask != r.Dest&r.Mask {
			continue
		}
		ones := bits.OnesCount32(r.Mask)
		bestOnes := bits.OnesCount32(best.Mask)
		if !found || ones > bestOnes || (ones == bestOnes && r.Metric1 < best.Metric1) {
			best = r
			found = true
		}
	}
	return best, found
}

// bestRouteForIPv4 在系统当前路由表中查找去往 dst 的最优路由，
// 用于给节点服务器 IP 写 /32 直连路由防回环
// （对应 SSTap config 里的 local_connection_shortest_r_nexthop 机制）
func bestRouteForIPv4(dst net.IP, excludeIfIdx uint32) (mibIPForwardRow, bool) {
	rows, err := getIpForwardTable()
	if err != nil {
		return mibIPForwardRow{}, false
	}
	return bestRouteFromRows(rows, dst, excludeIfIdx)
}

// physicalInterfaceName 返回去往 host 的物理出口网卡名（必须在分流路由铺好之前调用）。
// 用途：把 sing-box 出站显式绑定到物理网卡，避免 TUN 起来之后
// auto_detect_interface 把出站误判到 TUN 上，使直连流量（含 DNS 查询）被自己的
// 分流路由吸回 tun-in，触发 "DNS query loopback in transport[...]" 死循环。
func physicalInterfaceName(host string) string {
	for _, ip := range lookupNodeIPv4s(host) {
		base, ok := bestRouteForIPv4(ip, 0)
		if !ok || base.IfIndex == 0 {
			continue
		}
		iface, err := net.InterfaceByIndex(int(base.IfIndex))
		if err != nil || iface == nil || iface.Name == "" || iface.Name == tunIfaceName {
			continue
		}
		return iface.Name
	}
	return ""
}

// lookupNodeIPv4s 解析节点服务器的 IPv4 地址（最多 4 个）；Address 为 IP 字面量时直接返回
func lookupNodeIPv4s(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []net.IP{v4}
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4)
			if len(out) >= 4 {
				break
			}
		}
	}
	return out
}

// rangeToCIDRs 将闭区间 [start, end] 拆成 CIDR 列表
func rangeToCIDRs(start, end uint64) []net.IPNet {
	var out []net.IPNet
	for start <= end {
		align := uint64(1) << 32
		if start != 0 {
			align = start & (^start + 1) // 最低置位比特 = 最大对齐块
		}
		rem := end - start + 1
		size := align
		if rem < size {
			size = 1
			for size*2 <= rem {
				size *= 2
			}
		}
		prefixLen := 32 - (bits.Len64(size) - 1)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(start))
		mask := net.CIDRMask(prefixLen, 32)
		out = append(out, net.IPNet{IP: ip.Mask(mask), Mask: mask})
		start += size
	}
	return out
}

// computeBypassRoutes 计算需要送进虚拟网卡的 CIDR 列表 =
// 全网空间 - 中国大陆 IP（geo/cn-routes.txt）- 保留网段
// 等价 SSTap「Skip all China IP」规则集生成的路由表
func computeBypassRoutes() []net.IPNet {
	const full = uint64(1) << 32
	type rng struct{ s, e uint64 }

	var blocks []rng
	addCIDR := func(s string) {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil || ipnet.IP.To4() == nil {
			return
		}
		ones, _ := ipnet.Mask.Size()
		start := uint64(binary.BigEndian.Uint32(ipnet.IP.To4()))
		size := uint64(1) << (32 - ones)
		blocks = append(blocks, rng{start, start + size - 1})
	}
	for _, line := range strings.Split(cnRoutesTxt, "\n") {
		addCIDR(line)
	}
	for _, r := range reservedCIDRs {
		addCIDR(r)
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

// tunVerbose 自检（--tun-selftest）时输出的逐步日志；正常运行保持安静
var tunVerbose bool

func vlog(format string, args ...interface{}) {
	if tunVerbose {
		fmt.Printf("[tun] "+format+"\n", args...)
	}
}

// applySstapRouting 虚拟网卡就绪后写入整套 SSTap 式网络配置。
// 返回写入物理网卡的节点直连路由（断开时需回收）与 TUN 上生效的分流路由条数。
func applySstapRouting(node NodeItem, tunIdx uint32) (hostRoutes []mibIPForwardRow, routed int, err error) {
	hidden := &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}

	// 0) DNS 劫持生效前，先用系统 DNS 解析节点服务器地址（此刻分流路由未铺，走物理出口无回环）
	nodeIPs := lookupNodeIPv4s(node.Address)
	if len(nodeIPs) == 0 {
		return nil, 0, fmt.Errorf("failed to resolve IPv4 address of node %s (IPv6-only nodes are not supported in TUN mode)", node.Address)
	}

	// 1) 网卡 metric 抢到最高 + 系统 DNS 指向劫持地址（等价 SSTap 设置 TAP 适配器 DNS/跃点数）
	ps := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %d -InterfaceMetric %d; Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses '%s'",
			tunIdx, tunMetric, tunIdx, tunDnsAddr))
	ps.SysProcAttr = hidden
	if out, err := ps.CombinedOutput(); err != nil {
		return nil, 0, fmt.Errorf("failed to configure adapter DNS/metric: %v: %s", err, strings.TrimSpace(string(out)))
	}

	gw := net.ParseIP(tunGateway)

	// 2) DNS 劫持地址送进 TUN（系统 DNS 查询会被 sing-box port53 规则接管）
	_, dnsNet, _ := net.ParseCIDR(tunDnsAddr + "/32")
	if err := addRoute2(tunIdx, *dnsNet, gw, 1); err != nil {
		return nil, 0, fmt.Errorf("failed to write DNS hijack route: %w", err)
	}

	// 3) 节点服务器 IP 写 /32 直连路由防回环（沿系统真实最优路由，支持 on-link 网关/PPPoE）
	for _, ip := range nodeIPs {
		base, ok := bestRouteForIPv4(ip, tunIdx)
		if !ok {
			vlog("no best route found for node IP %s", ip)
			continue
		}
		vlog("node %s -> base route ifIdx=%d nextHop=%s metric=%d",
			ip, base.IfIndex, dwordToIP(base.NextHop), base.Metric1)
		row := mibIPForwardRow{
			Dest:    ipToDword(ip),
			Mask:    0xFFFFFFFF,
			NextHop: base.NextHop,
			IfIndex: base.IfIndex,
			Type:    base.Type,
			// 合成 metric = 物理 NIC 接口 metric + 1（该网卡上最高优先级）
			Metric1: interfaceMetric4(base.IfIndex) + 1,
		}
		if row.Type != ipRouteTypeDirect && row.Type != ipRouteTypeIndirect {
			if row.NextHop == 0 {
				row.Type = ipRouteTypeDirect
			} else {
				row.Type = ipRouteTypeIndirect
			}
		}
		if err := addRouteRow(&row); err != nil {
			vlog("addRouteRow(%s/32) failed: %v", ip, err)
			continue
		}
		hostRoutes = append(hostRoutes, row)
	}
	if len(hostRoutes) == 0 {
		return hostRoutes, 0, fmt.Errorf("failed to write direct host route: system route to %s not found", nodeIPs[0])
	}

	// 4) 大陆以外的全部 CIDR -> TUN（SSTap「不代理中国 IP」分流）
	var firstErr error
	for _, r := range computeBypassRoutes() {
		if err := addRoute2(tunIdx, r, gw, routeMetric); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		routed++
	}
	return hostRoutes, routed, firstErr
}

// removeHostRoutes 回收写入物理网卡的节点 /32 直连路由，返回成功删除的条数
func removeHostRoutes(routes *[]mibIPForwardRow) int {
	if routes == nil || len(*routes) == 0 {
		return 0
	}
	n := 0
	for _, r := range *routes {
		row := mibIPForwardRow{
			Dest:    r.Dest,
			Mask:    r.Mask,
			NextHop: r.NextHop,
			IfIndex: r.IfIndex,
		}
		if deleteRouteRow(&row) == nil {
			n++
		}
	}
	*routes = nil
	return n
}

// addTunIPv6Route 把 IPv6 全局单播 2000::/3 送进虚拟网卡，堵住 IPv6 泄漏。
// 旧版 IP Helper 路由 API（CreateIpForwardEntry）不支持 IPv6，因此与
// 网卡 metric/DNS 一样走 PowerShell 的 New-NetRoute（ActiveStore 不持久化，重启自动消失）。
// 只接管 2000::/3 而不是 ::/0：ULA (fc00::/7) 与链路本地 (fe80::/10) 保持系统原有行为。
func addTunIPv6Route(ifIdx uint32) error {
	ps := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("New-NetRoute -InterfaceIndex %d -DestinationPrefix '2000::/3' -NextHop '%s' -RouteMetric %d -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
			ifIdx, tunGateway6, routeMetric))
	ps.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	if out, err := ps.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeTunIPv6Route 回收写入虚拟网卡的 IPv6 分流路由（尽力而为；
// 网卡销毁时系统也会自动回收，失败静默忽略）
func removeTunIPv6Route(ifIdx uint32) {
	ps := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Remove-NetRoute -InterfaceIndex %d -DestinationPrefix '2000::/3' -Confirm:$false -ErrorAction SilentlyContinue", ifIdx))
	ps.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	_ = ps.Run()
}

// ------------------------- 生命周期 -------------------------

// createKillOnCloseJob 创建关闭即杀进程的 Job Object。
// sing-box 挂进该 Job 后，主进程无论正常退出、崩溃还是被强杀，
// 子进程都会被系统回收 → wintun 适配器随之销毁 → 其上路由由系统自动清除，根治孤儿进程。
func createKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// killOrphanSingBox 只杀掉由本程序释放的那个 sing-box.exe（按可执行文件完整路径匹配），
// 清理上个实例被强杀时遗留的孤儿进程 —— 它会占住同名 TUN 适配器导致下次启动失败。
// 不做 taskkill /IM 全量匹配：用户可能同时运行着其它 sing-box 软件（官方客户端等），不能误杀。
func killOrphanSingBox(exePath string) {
	ps := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" | Where-Object { $_.ExecutablePath -eq '%s' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }", exePath))
	ps.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	_ = ps.Run()
	time.Sleep(300 * time.Millisecond)
}

// waitForTunIface 轮询等待虚拟网卡就绪；sing-box 进程退出则立刻报错
func waitForTunIface(procDone <-chan struct{}) (uint32, error) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		ifaces, _ := net.Interfaces()
		for _, it := range ifaces {
			if it.Name == tunIfaceName {
				return uint32(it.Index), nil
			}
		}
		select {
		case <-procDone:
			return 0, fmt.Errorf("sing-box process exited, virtual interface %s not ready (check %%APPDATA%%\\KNcloud\\sing-box-run.log)", tunIfaceName)
		case <-time.After(300 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("timeout waiting for virtual interface %s", tunIfaceName)
		}
	}
}

// waitForAdapterGone 等待残留虚拟网卡完全消失（pnputil 删除是异步的，
// 不等干净就启动 sing-box 会报 "Cannot create a file when that file already exists"）
func waitForAdapterGone(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := net.InterfaceByName(tunIfaceName); err != nil {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// startTunLocked 启动 sing-box 子进程并铺好 SSTap 式分流路由（调用方需持有写锁）。
// 全程同步：返回成功时虚拟网卡、DNS 劫持与分流路由均已生效；任何一步失败都完整回滚。
func (a *App) startTunLocked(isRetry bool) error {
	a.stopTunLocked()

	// 清理本程序遗留的 sing-box 孤儿进程（上个实例被强杀时可能遗留，会占住同名 TUN 适配器）
	exePath, err := ensureSingBoxBin()
	if err != nil {
		return fmt.Errorf("failed to unpack sing-box binary: %w", err)
	}
	killOrphanSingBox(exePath)
	// 删除残留的 wintun 设备实例（kill 无法让 sing-box 自行清理，残留设备会导致同名适配器创建失败）
	if removed, remaining := removeResidualWintunDevices(); removed > 0 || remaining > 0 {
		if remaining > 0 {
			a.addLogInternal("warn", fmt.Sprintf("Removed %d stale wintun device(s), %d still present (TUN may fail to start; run as administrator)", removed, remaining))
		} else {
			a.addLogInternal("info", fmt.Sprintf("Removed %d stale wintun device(s) left by a previous run", removed))
		}
	}
	waitForAdapterGone(5 * time.Second)

	cfgDir, _ := appConfigDir()
	// TUN 需要 wintun.dll 才能创建虚拟网卡，必须和 sing-box.exe 放同一目录
	if _, err := ensureWintunDLL(cfgDir); err != nil {
		return fmt.Errorf("failed to unpack wintun.dll: %w", err)
	}
	srsPath := filepath.Join(cfgDir, "geosite-cn.srs")
	if st, err := os.Stat(srsPath); err != nil || st.Size() < 1024 {
		if err := os.WriteFile(srsPath, geositeCnSrs, 0644); err != nil {
			return fmt.Errorf("failed to unpack geosite-cn.srs: %w", err)
		}
	}

	var node *NodeItem
	for i := range a.nodes {
		if a.nodes[i].Active {
			node = &a.nodes[i]
			break
		}
	}
	if node == nil {
		return fmt.Errorf("no node selected")
	}

	// 解析节点服务器地址对应的物理出口网卡，用于把出站显式绑定到物理网卡。
	// 必须在分流路由铺好之前算（此刻路由表里还没有 TUN 的条目，能拿到真实的物理出口）。
	bindIface := physicalInterfaceName(node.Address)
	if bindIface == "" {
		a.addLogInternal("warn", "Physical egress interface not detected; outbound loop protection is disabled")
	}

	cfgJSON, err := buildTunConfigJSON(*node, srsPath, bindIface)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(cfgDir, "sing-box-tun.json")
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
		return err
	}

	cmd := exec.Command(exePath, "run", "-c", cfgPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow | syscall.CREATE_NEW_PROCESS_GROUP,
	}
	logPath := filepath.Join(cfgDir, "sing-box-run.log")
	// O_TRUNC：每次启动重写运行日志。旧实现用 O_APPEND 且级别为 warn，
	// 导致日志无限增长且看不到关键的路由/接口探测信息。
	if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
		cmd.Stdout = lf
		cmd.Stderr = lf
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	// KILL_ON_JOB_CLOSE Job：主进程异常退出时系统自动带走 sing-box
	if job, jerr := createKillOnCloseJob(); jerr == nil {
		// os.Process 不暴露句柄，按 PID 打开（Assign 需要的权限位）
		if ph, oerr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); oerr == nil {
			if err := windows.AssignProcessToJobObject(job, ph); err == nil {
				a.tunJob = job
			} else {
				windows.CloseHandle(job)
			}
			windows.CloseHandle(ph)
		} else {
			windows.CloseHandle(job)
		}
	}
	a.tunCmd = cmd
	a.tunProcDone = make(chan struct{})
	procDone := a.tunProcDone

	// 后台回收子进程退出事件（Wait 只能调用一次，停止逻辑依赖 procDone）
	go func() {
		waitErr := cmd.Wait()
		close(procDone)
		a.mu.Lock()
		if a.tunCmd == cmd {
			a.tunCmd = nil
			if a.tunRunning {
				a.tunRunning = false
				a.addLogInternal("warn", fmt.Sprintf("TUN process exited unexpectedly: %v", waitErr))
				// sing-box 崩溃后 wintun 适配器随进程销毁（其上分流路由由系统回收），
				// 但写入物理网卡的节点 /32 直连路由不会自动消失 —— 主动回收防残留
				a.stopTunLocked()
			}
		}
		a.mu.Unlock()
	}()

	// 同步等待虚拟网卡就绪（sing-box 创建 wintun 适配器一般 <2s）
	ifIdx, err := waitForTunIface(procDone)
	if err != nil {
		a.stopTunLocked()
		return err
	}
	a.tunIfaceIdx = ifIdx

	// SSTap 方案核心步骤：metric/DNS 劫持 + 服务器防回环路由 + 大陆外全量分流路由
	hostRoutes, nRouted, rtErr := applySstapRouting(*node, ifIdx)
	if rtErr != nil {
		a.stopTunLocked()
		return fmt.Errorf("SSTap routing setup failed: %v", rtErr)
	}
	a.tunHostRoutes = hostRoutes

	a.tunRunning = true
	a.tunWarmNode = *node // 记录热待机对应的出站节点，供软停止后的快速恢复比对
	a.tunWarm = false
	// IPv6 防泄漏：2000::/3 送进 TUN。失败不阻断启动（IPv4 分流不受影响），仅告警
	v6OK := addTunIPv6Route(ifIdx) == nil
	if !v6OK {
		a.addLogInternal("warn", "IPv6 split route setup failed; IPv6 traffic may bypass the tunnel")
	}
	bindInfo := "auto"
	if bindIface != "" {
		bindInfo = bindIface
	}
	a.addLogInternal("info", fmt.Sprintf("TUN interface %s ready | %d bypass routes + IPv6 leak protection (%v) | egress: %s | CN direct, others proxied | node: %s",
		tunIfaceName, nRouted, v6OK, bindInfo, node.Name))
	return nil
}

// warmStopTunLocked 软停止：撤除分流路由与 DNS 劫持，但保留 sing-box 进程与
// 虚拟网卡常驻待机 —— 再次开启 TUN 时无需重建网卡，秒级生效（调用方需持有写锁）。
func (a *App) warmStopTunLocked() {
	wasRunning := a.tunRunning

	// 1) 回收物理网卡上的节点 /32 直连路由
	if n := removeHostRoutes(&a.tunHostRoutes); n > 0 && wasRunning {
		a.addLogInternal("info", fmt.Sprintf("Removed %d node host routes", n))
	}

	// 2) 清空 TUN 网卡上的分流路由与 DNS（网卡保留，tunIfaceIdx 不复位，热恢复直接复用）
	if idx := a.tunIfaceIdx; idx != 0 {
		if n := deleteRoutesOnInterface(idx); n > 0 && wasRunning {
			a.addLogInternal("info", fmt.Sprintf("Removed %d split routes", n))
		}
		removeTunIPv6Route(idx)
		c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses", idx))
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		_ = c.Run()
	}

	if a.tunRunning {
		a.tunRunning = false
	}
	if a.tunCmd != nil {
		a.tunWarm = true
		a.addLogInternal("info", "TUN stopped (adapter kept in warm standby, next start is instant)")
	} else {
		a.tunWarm = false
	}
}

// stopTunLocked 停止 TUN 子进程并回收路由/DNS（调用方需持有写锁）。
// 即使子进程已意外退出，也会照常清理节点直连路由、分流路由与 DNS 劫持。
func (a *App) stopTunLocked() {
	wasRunning := a.tunRunning

	// 1) 回收物理网卡上的节点 /32 直连路由（防止切节点/断开后残留）
	if n := removeHostRoutes(&a.tunHostRoutes); n > 0 && wasRunning {
		a.addLogInternal("info", fmt.Sprintf("Removed %d node host routes", n))
	}

	// 2) 在适配器还活着时清干净 TUN 网卡上的分流路由与 DNS（网卡销毁时系统也会回收，此处主动清理）
	if idx := a.tunIfaceIdx; idx != 0 {
		if n := deleteRoutesOnInterface(idx); n > 0 && wasRunning {
			a.addLogInternal("info", fmt.Sprintf("Removed %d split routes", n))
		}
		removeTunIPv6Route(idx)
		c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses", idx))
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		_ = c.Run()
		a.tunIfaceIdx = 0
	}

	// 3) 关闭 Job 句柄：KILL_ON_JOB_CLOSE 会立即终止 sing-box 及其全部子进程
	if a.tunJob != 0 {
		windows.CloseHandle(a.tunJob)
		a.tunJob = 0
	}
	if a.tunCmd != nil {
		cmd := a.tunCmd
		a.tunCmd = nil
		select {
		case <-a.tunProcDone:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	a.tunProcDone = nil

	removeResidualWintunDevices()
	waitForAdapterGone(5 * time.Second)

	if a.tunRunning {
		a.tunRunning = false
		a.addLogInternal("info", "TUN stopped, all traffic back to direct")
	}
	a.tunRunning = false
	a.tunWarm = false
	a.tunWarmNode = NodeItem{}
}

// indexFoldASCII 在 s 中查找 ASCII 子串 sub（大小写不敏感），返回字节下标；找不到返回 -1。
// 逐字节比较、不做 UTF-8 解码，因此对中文 Windows 下 pnputil 的 GBK 输出同样安全。
func indexFoldASCII(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 || m > n {
		return -1
	}
	for i := 0; i+m <= n; i++ {
		match := true
		for j := 0; j < m; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ownWintunDescHints 本程序历史实现创建过的 wintun 适配器描述关键字。
// 只删除描述命中这些关键字的设备，避免误删 WireGuard / 其它 VPN 的 wintun 适配器：
//   - "sing-tun"    当前 TUN 方案（内嵌 sing-box）创建的适配器
//   - "xray tunnel" 早期进程内 Xray TUN 实验创建的适配器（该方案已废弃，但其残留
//                   适配器可能还在用户系统里，需要一并清理）
//   - tunIfaceName  按网卡名兜底
var ownWintunDescHints = []string{"sing-tun", "xray tunnel", tunIfaceName}

// pnputilPath 返回可用的 pnputil.exe 绝对路径，找不到时退回 "pnputil"（走 PATH）。
// 为什么不直接用 exec.Command("pnputil")：某些启动方式（服务、精简环境变量、非交互 shell）
// 下 PATH 里没有 System32，会直接报 "executable file not found"，清理静默失效。
// 另外 32 位进程访问 System32 会被 WOW64 重定向到 SysWOW64，而那里没有 pnputil.exe，
// 所以额外尝试 Sysnative（32 位进程绕过重定向的别名）。
func pnputilPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	for _, p := range []string{
		filepath.Join(root, "System32", "pnputil.exe"),
		filepath.Join(root, "Sysnative", "pnputil.exe"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "pnputil"
}

// isPnpRecordStart 判断 pnputil /enum-devices 输出中的某一行是否为新的设备记录首行（实例 ID 行）。
// 用于把描述行的查找严格限制在本设备记录内，避免跨到下一条记录造成误判。
func isPnpRecordStart(line string) bool {
	if indexFoldASCII(line, "实例 ID") >= 0 || indexFoldASCII(line, "Instance ID") >= 0 {
		return true
	}
	// 兜底：记录首行一定带设备实例路径
	for _, p := range []string{"SWD\\", "ROOT\\", "USB\\", "PCI\\", "ACPI\\"} {
		if indexFoldASCII(line, p) >= 0 {
			return true
		}
	}
	return false
}

// parseOwnWintunDeviceIDs 从 pnputil /enum-devices 的输出中解析出本程序遗留的
// wintun 设备实例 ID。只认设备描述里带本程序特征（sing-tun / Xray Tunnel / 网卡名）的记录，
// 避免误删 WireGuard 等其它软件安装的 wintun 设备。
//
// 历史 bug（本函数存在的原因）：旧实现用 strings.Index 做大小写敏感的 "SWD\WINTUN\" 匹配，
// 而 pnputil 实际输出是 "SWD\Wintun\"（仅首字母大写）—— 于是永远匹配不到任何设备，
// 残留设备只增不减，最终 sing-box 每次启动都报
// "configure tun interface: Cannot create a file when that file already exists"。
func parseOwnWintunDeviceIDs(out string) []string {
	lines := strings.Split(out, "\n")
	seen := map[string]bool{}
	var ids []string
	for i, line := range lines {
		idx := indexFoldASCII(line, "SWD\\WINTUN\\")
		if idx < 0 {
			continue
		}
		id := strings.TrimSpace(line[idx:])
		if id == "" || seen[id] {
			continue
		}
		// 设备描述行紧随实例 ID 行之后。扫描范围严格截止到下一条记录首行，
		// 否则会把下一条记录（例如别人的 WireGuard 适配器）的描述误算成本设备的。
		own := false
		for j := i + 1; j < len(lines) && j <= i+10; j++ {
			l := lines[j]
			if isPnpRecordStart(l) {
				break
			}
			for _, hint := range ownWintunDescHints {
				if indexFoldASCII(l, hint) >= 0 {
					own = true
					break
				}
			}
			if own {
				break
			}
		}
		if !own {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

// enumerateOwnWintunDevices 枚举本程序遗留的 wintun 设备实例 ID
func enumerateOwnWintunDevices() []string {
	hidden := &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	enumCmd := exec.Command(pnputilPath(), "/enum-devices")
	enumCmd.SysProcAttr = hidden
	out, err := enumCmd.Output()
	if err != nil {
		return nil
	}
	return parseOwnWintunDeviceIDs(string(out))
}

// removeResidualWintunDevices 删除残留的 wintun 设备实例（sing-box 被强杀时遗留），
// 返回 (删除条数, 剩余条数)。剩余不为 0 说明清理失败（通常是没以管理员身份运行）。
func removeResidualWintunDevices() (removed, remaining int) {
	hidden := &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	exe := pnputilPath()
	for _, id := range enumerateOwnWintunDevices() {
		c := exec.Command(exe, "/remove-device", id)
		c.SysProcAttr = hidden
		if err := c.Run(); err == nil {
			removed++
		}
	}
	remaining = len(enumerateOwnWintunDevices())
	return removed, remaining
}

// tunNodeMatches 判断热待机的 sing-box 出站节点与目标节点是否一致
// （配置在启动时烧录，节点变了必须冷启动重建）。
func tunNodeMatches(a, b NodeItem) bool {
	return a.Protocol == b.Protocol && a.Address == b.Address && a.Port == b.Port && a.UUID == b.UUID
}

// SimpleConnect 简易模式一键连接/断开：SSTap 方案分流全局代理（与内核代理模式互斥）。
// 关闭时 sing-box 与虚拟网卡进入热待机（仅撤路由，进程与网卡常驻），
// 再次开启且节点未变时只需重铺路由，秒级生效；节点变了才冷启动重建。
func (a *App) SimpleConnect(start bool) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if start {
		if !isElevated() {
			a.addLogInternal("error", "TUN mode requires administrator privileges")
			return a.tunRunning, fmt.Errorf("TUN global proxy requires administrator privileges")
		}

		var node *NodeItem
		for i := range a.nodes {
			if a.nodes[i].Active {
				node = &a.nodes[i]
				break
			}
		}
		if node == nil {
			return a.tunRunning, fmt.Errorf("no node selected")
		}

		// 热待机命中：sing-box 与虚拟网卡仍在线且出站节点未变 —— 重铺路由即可
		if a.tunWarm && a.tunCmd != nil && a.tunIfaceIdx != 0 && tunNodeMatches(a.tunWarmNode, *node) {
			// 与内核模式互斥：先停内核、还原系统代理
			a.tunReplacedCore = a.coreRunning
			if a.coreRunning {
				a.stopCoreLocked()
				a.coreRunning = false
				if a.systemProxy {
					setWindowsSystemProxy(false, "")
					a.systemProxy = false
				}
			}
			hostRoutes, nRouted, rtErr := applySstapRouting(*node, a.tunIfaceIdx)
			if rtErr == nil {
				a.tunHostRoutes = hostRoutes
				addTunIPv6Route(a.tunIfaceIdx)
				a.tunRunning = true
				a.addLogInternal("info", fmt.Sprintf("TUN resumed from warm standby | %d bypass routes | node: %s", nRouted, node.Name))
				a.savePersisted()
				tray.requestRebuild()
				return a.tunRunning, nil
			}
			a.addLogInternal("warn", fmt.Sprintf("Warm standby resume failed (%v), falling back to cold start", rtErr))
			a.stopTunLocked()
		}

		// 冷启动：完整重建 sing-box 与虚拟网卡（首次开启 / 节点变更后）
		a.tunReplacedCore = a.coreRunning
		if a.coreRunning {
			a.stopCoreLocked()
			a.coreRunning = false
			if a.systemProxy {
				setWindowsSystemProxy(false, "")
				a.systemProxy = false
			}
			a.addLogInternal("info", "Core proxy stopped, switching to TUN mode")
		}
		if err := a.startTunLocked(false); err != nil {
			a.tunRunning = false
			a.addLogInternal("error", fmt.Sprintf("TUN start failed: %v", err))
			a.savePersisted()
			return false, err
		}
	} else {
		// 软停止：撤路由进热待机（sing-box 与网卡常驻，下次开启秒级恢复）
		a.warmStopTunLocked()
		// TUN 开启前内核与系统代理在跑：断开 TUN 后恢复常规代理模式，
		// 避免用户点一下托盘开关就落得「什么都没连」的状态
		if a.tunReplacedCore && !a.coreRunning {
			if err := a.startCoreLocked(); err != nil {
				a.addLogInternal("warn", fmt.Sprintf("Core proxy not restored after TUN stop: %v", err))
			} else {
				a.coreRunning = true
				server := fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort)
				if err := setWindowsSystemProxy(true, server); err != nil {
					a.addLogInternal("error", fmt.Sprintf("Failed to re-enable system proxy after TUN stop: %v", err))
				} else {
					a.systemProxy = true
				}
				a.addLogInternal("info", fmt.Sprintf("TUN stopped, core proxy restored -> %s", server))
			}
		}
		a.tunReplacedCore = false
	}
	a.savePersisted()
	tray.requestRebuild()
	return a.tunRunning, nil
}

// tunTrafficSample 通过 Windows IP Helper 采样 TUN 网卡流量（简易/全局模式下的真实速率）
func (a *App) tunTrafficSample() (up, down int64, ok bool) {
	a.mu.RLock()
	idx := a.tunIfaceIdx
	running := a.tunRunning
	a.mu.RUnlock()
	if !running || idx == 0 {
		return 0, 0, false
	}
	row := windows.MibIfRow2{}
	row.InterfaceIndex = idx
	if err := windows.GetIfEntry2Ex(0, &row); err != nil {
		return 0, 0, false
	}
	return int64(row.OutOctets), int64(row.InOctets), true
}
