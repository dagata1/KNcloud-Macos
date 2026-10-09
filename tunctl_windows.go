package main

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

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

// defaultRouteOps 生产环境的系统路由表操作（IP Helper API）。
func defaultRouteOps() routeOps { return winRouteOps{} }

// prepareTunPrivileges Windows 上 TUN 依赖进程本身以管理员身份运行（tunStartLocked 里检查），无需额外准备。
func prepareTunPrivileges() error { return nil }
