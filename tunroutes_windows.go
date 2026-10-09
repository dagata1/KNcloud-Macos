package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

var (
	procCreateIpForwardEntry2    = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = iphlpapi.NewProc("DeleteIpForwardEntry2")
	procInitializeIpForwardEntry = iphlpapi.NewProc("InitializeIpForwardEntry")
)

// mibIPForwardRow2 按 C 的 MIB_IPFORWARD_ROW2 手工排布（共 104 字节）。
// x/sys 的 MibIpForwardRow2 里 SOCKADDR_INET 按 2 字节对齐，与系统的 4 字节对齐不符，
// 字段整体错位，所以这里用定长字节数组自己排。
type mibIPForwardRow2 struct {
	InterfaceLuid        uint64   // 0
	InterfaceIndex       uint32   // 8
	DestinationPrefix    [32]byte // 12: SOCKADDR_INET(28) + PrefixLength(1) + pad(3)
	NextHop              [28]byte // 44: SOCKADDR_INET
	SitePrefixLength     uint8    // 72
	_                    [3]byte
	ValidLifetime        uint32 // 76
	PreferredLifetime    uint32 // 80
	Metric               uint32 // 84
	Protocol             uint32 // 88
	Loopback             uint8  // 92
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32 // 96
	Origin               uint32 // 100
}

// 编译期断言：布局必须是 104 字节
var _ = [1]struct{}{}[unsafe.Sizeof(mibIPForwardRow2{})-104]

func putSockaddrIn4(dst []byte, ip uint32) {
	for i := range dst[:28] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint16(dst[0:2], syscall.AF_INET)
	binary.BigEndian.PutUint32(dst[4:8], ip)
}

func makeForwardRow2(r routeEntry) mibIPForwardRow2 {
	var row mibIPForwardRow2
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = r.IfIndex
	putSockaddrIn4(row.DestinationPrefix[:28], r.Dest)
	row.DestinationPrefix[28] = r.Bits
	putSockaddrIn4(row.NextHop[:], r.NextHop)
	row.Metric = r.Metric
	row.Protocol = ipProtoNetMgmt
	return row
}

type winRouteOps struct{}

func (winRouteOps) AddRoute(r routeEntry) error {
	row := makeForwardRow2(r)
	ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	switch ret {
	case 0:
		return nil
	case 5010: // ERROR_OBJECT_ALREADY_EXISTS
		return errRouteExists
	}
	return syscall.Errno(ret)
}

func (winRouteOps) DeleteRoute(r routeEntry) error {
	row := makeForwardRow2(r)
	ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	switch ret {
	case 0:
		return nil
	case 1168, 2: // ERROR_NOT_FOUND / ERROR_FILE_NOT_FOUND
		return errRouteNotFound
	}
	return syscall.Errno(ret)
}

// physHopFor 查找去往 ip 的物理出口（排除 TUN 网卡与回环），
// 用于节点 /32 与绕过网段。TUN 运行中也能正确返回物理出口。
func physHopFor(ip net.IP, tunIdx uint32) (physHop, bool) {
	row, ok := bestRouteForIPv4(ip, tunIdx)
	if !ok || row.IfIndex == 0 || row.IfIndex == tunIdx {
		return physHop{}, false
	}
	if row.IfIndex == nativeTunIdxCached() {
		return physHop{}, false
	}
	return physHop{IfIndex: row.IfIndex, NextHop: ipToU32(dwordToIP(row.NextHop))}, true
}

// nativeTunIdxCached 原生 SSTap TAP 网卡索引（不存在返回 0），防止把它当作物理出口。
func nativeTunIdxCached() uint32 {
	if idx, err := nativeTunIfaceIndex(); err == nil {
		return idx
	}
	return 0
}
