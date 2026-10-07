//go:build windows && amd64

package main

// tunwfp.go —— TUN 开启期间堵住 Windows 的 DNS 旁路。
//
// Windows 的「智能多宿主名称解析」(SMHNR) 会把每个查询同时发给所有网卡的 DNS，且按
// 网卡绑定发出、不看路由表：TUN 网卡 DNS=198.18.0.2、metric=1 也挡不住系统同时去问
// 物理网卡上的运营商 DNS，而运营商应答通常更快 —— 全局模式下海外域名也拿到被污染的答案，
// DNS 劫持名存实亡（实测：每个系统解析请求都有 A/AAAA 两包发往物理网卡 DNS）。
//
// 做法与 OpenVPN block-outside-dns / sing-tun strict_route 相同：用 WFP 动态会话加过滤器，
// 拦截「发往物理网卡 DNS 服务器的 53 端口连接」，本进程（DNS 中继、Xray）放行。
// 动态会话的过滤器随句柄关闭或进程退出（含崩溃、kill -9）自动消失，不会残留。

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fwpuclnt                      = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmGetAppIdFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
)

var (
	fwpmLayerAleAuthConnectV4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	fwpmLayerAleAuthConnectV6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	fwpmConditionIPRemotePort = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	fwpmConditionIPRemoteAddr = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	fwpmConditionAleAppID     = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
)

const (
	fwpUint8           = 1
	fwpUint16          = 2
	fwpUint32          = 3
	fwpByteArray16Type = 11
	fwpByteBlobType    = 12
	fwpMatchEqual      = 0
	fwpActionBlock     = 0x1001
	fwpActionPermit    = 0x1002
	fwpmSessionDynamic = 0x1
	rpcCAuthnWinNT     = 10
)

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpValue0 struct {
	typ   uint32
	value uintptr // union：标量直接存值，数组/blob 存指针
}

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	providerContextKey  [2]uint64 // union { UINT64 rawContext; GUID providerContextKey; }（8 字节对齐）
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

// 编译期断言：与 fwpmtypes.h 的 amd64 布局一致
var (
	_ = [1]struct{}{}[unsafe.Sizeof(fwpmFilter0{})-200]
	_ = [1]struct{}{}[unsafe.Offsetof(fwpmFilter0{}.action)-128]
	_ = [1]struct{}{}[unsafe.Offsetof(fwpmFilter0{}.providerContextKey)-152]
	_ = [1]struct{}{}[unsafe.Sizeof(fwpmFilterCondition0{})-40]
	_ = [1]struct{}{}[unsafe.Sizeof(fwpmSession0{})-72]
)

// tunDNSGuard 一个 WFP 动态会话（Close 或进程退出即撤销全部过滤器）
type tunDNSGuard struct {
	engine  uintptr
	filters int
}

func (g *tunDNSGuard) Close() {
	if g == nil || g.engine == 0 {
		return
	}
	procFwpmEngineClose0.Call(g.engine)
	g.engine = 0
}

// physDNSServers 物理网卡上配置的 DNS 服务器（运营商/DHCP 下发的那组）
func physDNSServers(ifIdx uint32) (v4, v6 []net.IP) {
	var size uint32 = 16 << 10
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, nil
		}
		for a := aa; a != nil; a = a.Next {
			if a.IfIndex != ifIdx {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				ip := d.Address.IP()
				if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					v4 = append(v4, ip4)
				} else if !ip.Equal(net.ParseIP("fec0:0:0:ffff::1")) && !ip.Equal(net.ParseIP("fec0:0:0:ffff::2")) && !ip.Equal(net.ParseIP("fec0:0:0:ffff::3")) {
					v6 = append(v6, ip)
				}
			}
		}
		return v4, v6
	}
	return nil, nil
}

// newTunDNSGuard 拦截发往 servers（物理网卡 DNS）的 53 端口连接，本进程放行。
func newTunDNSGuard(v4, v6 []net.IP) (*tunDNSGuard, error) {
	if len(v4)+len(v6) == 0 {
		return nil, nil
	}
	if err := procFwpmEngineOpen0.Find(); err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString("KNcloud TUN DNS leak guard")
	session := fwpmSession0{displayData: fwpmDisplayData0{name: name}, flags: fwpmSessionDynamic}
	g := &tunDNSGuard{}
	if r, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&g.engine))); r != 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0: 0x%x", r)
	}
	ok := false
	defer func() {
		if !ok {
			g.Close()
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeW, _ := windows.UTF16PtrFromString(exe)
	var appID *fwpByteBlob
	if r, _, _ := procFwpmGetAppIdFromFileName0.Call(uintptr(unsafe.Pointer(exeW)), uintptr(unsafe.Pointer(&appID))); r != 0 {
		return nil, fmt.Errorf("FwpmGetAppIdFromFileName0: 0x%x", r)
	}
	defer procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&appID)))

	add := func(layer windows.GUID, action uint32, weight uint8, conds []fwpmFilterCondition0) error {
		f := fwpmFilter0{
			displayData:         fwpmDisplayData0{name: name},
			layerKey:            layer,
			weight:              fwpValue0{typ: fwpUint8, value: uintptr(weight)},
			numFilterConditions: uint32(len(conds)),
			action:              fwpmAction0{typ: action},
		}
		if len(conds) > 0 {
			f.filterCondition = &conds[0]
		}
		var id uint64
		if r, _, _ := procFwpmFilterAdd0.Call(g.engine, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id))); r != 0 {
			return fmt.Errorf("FwpmFilterAdd0: 0x%x", r)
		}
		g.filters++
		return nil
	}
	port := fwpmFilterCondition0{fieldKey: fwpmConditionIPRemotePort, matchType: fwpMatchEqual, conditionValue: fwpValue0{typ: fwpUint16, value: 53}}
	for _, layer := range []windows.GUID{fwpmLayerAleAuthConnectV4, fwpmLayerAleAuthConnectV6} {
		app := []fwpmFilterCondition0{{fieldKey: fwpmConditionAleAppID, matchType: fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpByteBlobType, value: uintptr(unsafe.Pointer(appID))}}}
		if err := add(layer, fwpActionPermit, 15, app); err != nil {
			return nil, err
		}
	}
	for _, ip := range v4 {
		conds := []fwpmFilterCondition0{port, {fieldKey: fwpmConditionIPRemoteAddr, matchType: fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpUint32, value: uintptr(ipToU32(ip))}}}
		if err := add(fwpmLayerAleAuthConnectV4, fwpActionBlock, 10, conds); err != nil {
			return nil, err
		}
	}
	addrs := make([][16]byte, len(v6)) // 堆上，FwpmFilterAdd0 期间有效即可
	for i, ip := range v6 {
		copy(addrs[i][:], ip.To16())
		conds := []fwpmFilterCondition0{port, {fieldKey: fwpmConditionIPRemoteAddr, matchType: fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpByteArray16Type, value: uintptr(unsafe.Pointer(&addrs[i]))}}}
		if err := add(fwpmLayerAleAuthConnectV6, fwpActionBlock, 10, conds); err != nil {
			return nil, err
		}
	}
	ok = true
	return g, nil
}
