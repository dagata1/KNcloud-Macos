package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

// hiddenProc 返回不带控制台窗口的进程属性。
// netsh / powershell / pnputil 都是控制台程序：直接 exec 会先闪一个黑框再关，
// 关 TUN 时尤其明显。HideWindow 只隐藏首次窗口，CreationFlags 才是根治项。
func hiddenProc() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// flushDnsClientCache 清空系统 DNS 客户端缓存。
//
// 换节点后必须调用：浏览器与系统会缓存 A 记录，检测站 / CDN 可能继续命中
// 旧解析结果，导致「已切到新加坡、看到的却是韩国」的错觉。
//
// 优先走 ipconfig（秒级）；失败再退到 PowerShell 的
// Clear-DnsClientCache（某些精简系统缺少 ipconfig）。两者都是本机调用，
// 不需要管理员权限，因此非管理员路径下也能安全执行。
//
// 各命令都有较短的上限：调用方可能在等它（TUN 切换），宁可少清一次缓存也不能挂住。
func flushDnsClientCache() {
	if out, err := runHiddenWithin(8*time.Second, "ipconfig", "/flushdns"); err != nil {
		vlog("ipconfig /flushdns failed (%v): %s", err, strings.TrimSpace(string(out)))
		if out2, err2 := runHiddenWithin(15*time.Second, "powershell", "-NoProfile", "-NonInteractive",
			"-Command", "Clear-DnsClientCache"); err2 != nil {
			vlog("Clear-DnsClientCache failed (%v): %s", err2, strings.TrimSpace(string(out2)))
		}
	}
}

var (
	iphlpapi                        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestRoute                = iphlpapi.NewProc("GetBestRoute")
	procGetIpForwardTable           = iphlpapi.NewProc("GetIpForwardTable")
	procConvertInterfaceLuidToIndex = iphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procSetIpInterfaceEntry         = iphlpapi.NewProc("SetIpInterfaceEntry")
	procFreeMibTable                = iphlpapi.NewProc("FreeMibTable")
)

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

// clearTapAdapterDNS 清空网卡上残留的静态 DNS（回 DHCP）。
// 返回是否真的清掉了东西。
func clearTapAdapterDNS(ifIdx uint32) bool {
	// 参数是 address=all（不是 source=all —— 后者会被 netsh 判为非法参数）
	out, err := runHidden("netsh", "interface", "ipv4", "delete", "dnsservers",
		fmt.Sprintf("name=%d", ifIdx), "address=all")
	if err != nil {
		vlog("clear adapter IPv4 DNS (ifIdx=%d): %v: %s", ifIdx, err, strings.TrimSpace(string(out)))
	}
	// IPv6 也要清：设置过 IPv4 DNS 后，网卡上常会多出 fec0:: 系列占位 DNS，
	// 它会继续被系统选中去查 DNS，导致清完 IPv4 仍然解析失败。
	out6, err6 := runHidden("netsh", "interface", "ipv6", "delete", "dnsservers",
		fmt.Sprintf("interface=%d", ifIdx), "address=all")
	if err6 != nil {
		vlog("clear adapter IPv6 DNS (ifIdx=%d): %v: %s", ifIdx, err6, strings.TrimSpace(string(out6)))
	}
	return !adapterHasDns(ifIdx, tunDnsAddr)
}

// adapterHasDns 回读校验网卡是否真的配置了指定 DNS
// （netsh 参数写错时退出码仍为 0，只能靠回读确认）
func adapterHasDns(ifIdx uint32, want string) bool {
	out, err := runHidden("netsh", "interface", "ipv4", "show", "dnsservers",
		fmt.Sprintf("name=%d", ifIdx))
	if err != nil {
		return false
	}
	return strings.Contains(string(out), want)
}

// removeTapRoutesBulk 一次性清空虚拟网卡上的全部 IPv4 路由（分流 + DNS 劫持）。
//
// 为什么不用逐行 DeleteIpForwardEntry：
//  1. 断开（media-disconnected）状态网卡的路由对旧版 GetIpForwardTable 不可见，
//     枚举式删除会静默漏删 —— 每次开关泄漏上万条僵尸路由；
//  2. 逐行删除上万次会把关闭/切换路径拖到几十秒（表现为窗口关不掉）。
//
// PowerShell 的 Remove-NetRoute 走新版 IP Helper，断开网卡同样能删，且一条命令搞定。
//
// 该网卡由本程序专用（TAP 常驻），其上路由全部由本程序写入，可整体清空。
func removeTapRoutesBulk(ifIdx uint32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	psCmd := fmt.Sprintf(
		"Remove-NetRoute -InterfaceIndex %d -Confirm:$false -ErrorAction SilentlyContinue; "+
			"Remove-NetRoute -InterfaceIndex %d -DestinationPrefix '2000::/3' -Confirm:$false -ErrorAction SilentlyContinue",
		ifIdx, ifIdx)
	ps := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	ps.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := ps.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// addTunIPv6Route 把 IPv6 全局单播 2000::/3 送进虚拟网卡，堵住 IPv6 泄漏。
// 旧版 IP Helper 路由 API（CreateIpForwardEntry）不支持 IPv6，因此与
// 网卡 metric/DNS 一样走 PowerShell 的 New-NetRoute（ActiveStore 不持久化，重启自动消失）。
// 只接管 2000::/3 而不是 ::/0：ULA (fc00::/7) 与链路本地 (fe80::/10) 保持系统原有行为。
func addTunIPv6Route(ifIdx uint32) error {
	// 该路由的下一跳是网卡自身的 IPv6 地址；网卡没配这个地址时（原生 tun2socks
	// 路径只配 IPv4）写进去也没有意义，跳过而不是静默写一条无效路由。
	if !ifaceHasAddr(ifIdx, tunGateway6) {
		return nil
	}
	// 用 netsh 而非 PowerShell：本函数每次开关 TUN 都会调用，PowerShell 光启动
	// 加加载 NetIP 模块就要 4~5 秒，是「开 TUN 很慢」的主因。
	// 注意必须写 interface=（netsh 的 ipv6 子命令不接受 if= 缩写），且 netsh
	// 参数错误时退出码仍是 0，因此必须回读校验，不能只看 err。
	out, err := runHidden("netsh", "interface", "ipv6", "add", "route", "2000::/3", tunGateway6,
		fmt.Sprintf("interface=%d", ifIdx), fmt.Sprintf("metric=%d", splitRouteMetric),
		"store=active", "publish=no")
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	if !hasIPv6SplitRoute(ifIdx) {
		return fmt.Errorf("netsh did not create 2000::/3 on ifIdx=%d: %s", ifIdx, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeTunIPv6RouteFast 回收 2000::/3（netsh，约 0.2s；PowerShell 约 5s）
func removeTunIPv6RouteFast(ifIdx uint32) {
	_, _ = runHidden("netsh", "interface", "ipv6", "delete", "route", "2000::/3",
		fmt.Sprintf("interface=%d", ifIdx), "store=active")
}

// hasIPv6SplitRoute 回读校验 2000::/3 是否真的落在指定网卡上
func hasIPv6SplitRoute(ifIdx uint32) bool {
	out, err := runHidden("netsh", "interface", "ipv6", "show", "route",
		fmt.Sprintf("interface=%d", ifIdx))
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "2000::/3")
}
