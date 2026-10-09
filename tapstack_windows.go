package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// knTapGUID 常驻虚拟网卡的固定 GUID（对应 SSTap 的 {09794FC1-...}）。
// wintun 以 GUID 定位适配器：存在即复用，不存在才创建。
var knTapGUID = windows.GUID{
	Data1: 0x6e4a2c31,
	Data2: 0x8d5f,
	Data3: 0x4b9e,
	Data4: [8]byte{0xa2, 0x37, 0x6c, 0x15, 0xd9, 0xe4, 0x7b, 0x08},
}

// tapRingCapacity wintun 收发环大小（必须是 2 的幂，128KiB~64MiB）。
const tapRingCapacity = 0x800000

var (
	wintunModPath                  string
	wintunMod                      *windows.LazyDLL
	wintunProcOpenAdapter          *windows.LazyProc
	wintunProcCreateAdapter        *windows.LazyProc
	wintunProcCloseAdapter         *windows.LazyProc
	wintunProcStartSession         *windows.LazyProc
	wintunProcEndSession           *windows.LazyProc
	wintunProcGetReadWaitEvent     *windows.LazyProc
	wintunProcReceivePacket        *windows.LazyProc
	wintunProcReleaseReceivePacket *windows.LazyProc
	wintunProcAllocateSendPacket   *windows.LazyProc
	wintunProcSendPacket           *windows.LazyProc
	wintunProcGetAdapterLUID       *windows.LazyProc
	wintunLoaded                   sync.Once
	wintunLoadErr                  error
)

// loadWintunAPI 从 bin\wintun.dll 加载并解析 API（绝对路径加载，不依赖 DLL 搜索顺序）。
func loadWintunAPI() error {
	wintunLoaded.Do(func() {
		p, err := findResource("wintun.dll", "cores")
		if err != nil {
			wintunLoadErr = err
			return
		}
		wintunModPath = p

		mod := windows.NewLazyDLL(wintunModPath)
		pOpen := mod.NewProc("WintunOpenAdapter")
		pCreate := mod.NewProc("WintunCreateAdapter")
		pClose := mod.NewProc("WintunCloseAdapter")
		pStart := mod.NewProc("WintunStartSession")
		pEnd := mod.NewProc("WintunEndSession")
		pEvt := mod.NewProc("WintunGetReadWaitEvent")
		pRecv := mod.NewProc("WintunReceivePacket")
		pRel := mod.NewProc("WintunReleaseReceivePacket")
		pAlloc := mod.NewProc("WintunAllocateSendPacket")
		pSend := mod.NewProc("WintunSendPacket")
		pLUID := mod.NewProc("WintunGetAdapterLUID")
		if e := mod.Load(); e != nil {
			wintunLoadErr = e
			return
		}
		for _, p := range []*windows.LazyProc{pOpen, pCreate, pClose, pStart, pEnd, pEvt, pRecv, pRel, pAlloc, pSend, pLUID} {
			if e := p.Find(); e != nil {
				wintunLoadErr = e
				return
			}
		}
		wintunMod = mod
		wintunProcOpenAdapter = pOpen
		wintunProcCreateAdapter = pCreate
		wintunProcCloseAdapter = pClose
		wintunProcStartSession = pStart
		wintunProcEndSession = pEnd
		wintunProcGetReadWaitEvent = pEvt
		wintunProcReceivePacket = pRecv
		wintunProcReleaseReceivePacket = pRel
		wintunProcAllocateSendPacket = pAlloc
		wintunProcSendPacket = pSend
		wintunProcGetAdapterLUID = pLUID
	})
	return wintunLoadErr
}

func wintutCreatePersistentAdapter(name string) (adapter uintptr, err error) {
	namePtr, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, e
	}
	typePtr, e := windows.UTF16PtrFromString("KNcloud")
	if e != nil {
		return 0, e
	}
	// Wintun 0.14 返回适配器句柄，失败时通过 GetLastError 获取错误码。
	r1, _, callErr := wintunProcCreateAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(typePtr)),
		uintptr(unsafe.Pointer(&knTapGUID)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("WintunCreateAdapter failed: %v", callErr)
	}
	return r1, nil
}

func wintunOpenAdapterByName(name string) (uintptr, error) {
	namePtr, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, e
	}
	r1, _, callErr := wintunProcOpenAdapter.Call(uintptr(unsafe.Pointer(namePtr)))
	if r1 != 0 {
		return r1, nil
	}
	return 0, fmt.Errorf("WintunOpenAdapter failed: %v", callErr)
}

func wintunStartSession(adapter uintptr, capacity uint32) (session uintptr, err error) {
	r1, _, callErr := wintunProcStartSession.Call(adapter, uintptr(capacity))
	if r1 == 0 {
		return 0, fmt.Errorf("WintunStartSession failed: %v", callErr)
	}
	return r1, nil
}

// wintunAdapterIfIndex 由适配器 LUID 取系统接口索引
func wintunAdapterIfIndex(adapter uintptr) (uint32, error) {
	var luid uint64
	wintunProcGetAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))

	// 1. 优先使用 Windows NDIS 官方 LUID -> IfIndex 转换 API（无视 AF_INET 是否已在 MIB 登记）
	var ifIdx uint32
	ret, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&ifIdx)))
	if ret == 0 && ifIdx != 0 {
		return ifIdx, nil
	}

	// 2. 备用方式：轮询 net.InterfaceByName / GetIpInterfaceEntry
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if iface, err := net.InterfaceByName(tunIfaceName); err == nil && iface.Index > 0 {
			return uint32(iface.Index), nil
		}
		row := &windows.MibIpInterfaceRow{Family: 2 /*AF_INET*/, InterfaceLuid: luid}
		if err := windows.GetIpInterfaceEntry(row); err == nil && row.InterfaceIndex != 0 {
			return row.InterfaceIndex, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 最终兜底尝试 net.InterfaceByName
	if iface, err := net.InterfaceByName(tunIfaceName); err == nil && iface.Index > 0 {
		return uint32(iface.Index), nil
	}
	return 0, fmt.Errorf("ConvertInterfaceLuidToIndex failed (ret=%d), adapter %s not found", ret, tunIfaceName)
}

// tapPersistentAdapter 常驻适配器（进程生命周期内缓存句柄；适配器本身
// 长期存在于系统，进程退出也不销毁 —— 与 SSTap 的 TAP-Windows 一致）
type tapPersistentAdapter struct {
	mu      sync.Mutex
	rx      sync.Mutex // readLoop 的 Receive/Release 配对互斥
	tx      sync.Mutex // WritePackets 的 Allocate/Send 互斥（与 rx 分离：收发并行，回调内同步发包不自死锁）
	handle  uintptr
	session uintptr
	readEvt windows.Handle
	ifIdx   uint32
}

var knTap = &tapPersistentAdapter{}

// ensure 拿到常驻适配器并开启读写会话；已就绪则直接复用（幂等）。
func (p *tapPersistentAdapter) ensure() (ifIdx uint32, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.session != 0 {
		return p.ifIdx, nil
	}
	if err := loadWintunAPI(); err != nil {
		return 0, fmt.Errorf("wintun.dll unavailable: %v", err)
	}
	// 先尝试打开已存在的常驻适配器（SSTap 同款复用语义），不存在才创建
	adapter, aerr := wintunOpenAdapterByName(tunIfaceName)
	if aerr != nil {
		adapter, err = wintutCreatePersistentAdapter(tunIfaceName)
		if err != nil {
			return 0, fmt.Errorf("open: %v; create: %v", aerr, err)
		}
	}
	// 读写环大小：2MB 足够代理流量吞吐，内存占用可控
	session, err := wintunStartSession(adapter, tapRingCapacity)
	if err != nil {
		wintunProcCloseAdapter.Call(adapter)
		return 0, err
	}
	ifIdx, err = wintunAdapterIfIndex(adapter)
	if err != nil {
		wintunProcEndSession.Call(session)
		wintunProcCloseAdapter.Call(adapter)
		return 0, err
	}
	p.handle = adapter
	p.session = session
	r1, _, _ := wintunProcGetReadWaitEvent.Call(session)
	p.readEvt = windows.Handle(r1)
	p.ifIdx = ifIdx
	return ifIdx, nil
}

// closeSession 结束读写会话并关闭句柄。注意：不删除适配器 —— 它是常驻的。
func (p *tapPersistentAdapter) closeSession() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.session != 0 {
		wintunProcEndSession.Call(p.session)
		p.session = 0
	}
	if p.handle != 0 {
		wintunProcCloseAdapter.Call(p.handle)
		p.handle = 0
	}
	p.readEvt = 0
	p.ifIdx = 0
}

// tunLinkEndpoint 把 wintun 会话适配为 gvisor 的 LinkEndpoint。
// 收包：读环事件驱动，取出 IP 包按版本分发给协议栈；
// 发包：netstack 组好的 IP 包原样写回 wintun。
type tunLinkEndpoint struct {
	mtu        uint32
	adapter    *tapPersistentAdapter
	readEvt    windows.Handle
	stopCh     chan struct{}
	dispatcher stack.NetworkDispatcher
	stopped    sync.WaitGroup
	mu         sync.Mutex
}

func (e *tunLinkEndpoint) MTU() uint32 { return e.mtu }

func (e *tunLinkEndpoint) SetMTU(mtu uint32) { e.mtu = mtu }

func (e *tunLinkEndpoint) MaxHeaderLength() uint16 { return 0 }

func (e *tunLinkEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (e *tunLinkEndpoint) SetLinkAddress(a tcpip.LinkAddress) {}

func (e *tunLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0 // 无硬件校验和卸载：netstack 软件计算校验和
}

func (e *tunLinkEndpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
	if d != nil {
		e.stopped.Add(1)
		go e.readLoop(d)
	}
}

func (e *tunLinkEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcher != nil
}

func (e *tunLinkEndpoint) Wait() {}

// ARPHardwareType / AddHeader / ParseHeader：TUN 无链路层头，均为空实现
func (e *tunLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *tunLinkEndpoint) AddHeader(*stack.PacketBuffer) {}

func (e *tunLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// readLoop 从 wintun 读环持续取包注入 netstack。
// WaitForSingleObject 等待读环事件（有包立即唤醒，无包 200ms 超时醒来检查 stop）。
//
// 关键：先把包拷贝出来、立即 Release 并解锁，再投递给协议栈。
// DeliverNetworkPacket 是同步的，TCP/UDP 转发器可能在同一调用栈里同步回包
// （RST、ACK、ICMP），持着读锁投递会让发送路径自死锁；收发也不应串行。
func (e *tunLinkEndpoint) readLoop(d stack.NetworkDispatcher) {
	defer e.stopped.Done()
	// cgo 回调中的访问违例不允许带崩整个进程（尤其 gvisor 协议栈协程并发期）
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("[tapstack] readLoop panic recovered:", r)
		}
	}()
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}
		if e.readEvt != 0 {
			windows.WaitForSingleObject(e.readEvt, 200)
		} else {
			time.Sleep(50 * time.Millisecond)
		}
		e.mu.Lock()
		session := e.adapter.session
		disp := e.dispatcher
		e.mu.Unlock()
		if session == 0 || disp == nil {
			return
		}
		for {
			select {
			case <-e.stopCh:
				return
			default:
			}
			e.adapter.rx.Lock()
			var size uint32
			packet, _, _ := wintunProcReceivePacket.Call(session, uintptr(unsafe.Pointer(&size)))
			if packet == 0 {
				e.adapter.rx.Unlock()
				break // ERROR_NO_MORE_ITEMS：本轮读完
			}
			data := make([]byte, size)
			copy(data, unsafe.Slice((*byte)(unsafe.Pointer(packet)), size))
			// 第二参数是包指针（ReceivePacket 的返回值），不是长度
			wintunProcReleaseReceivePacket.Call(session, packet)
			e.adapter.rx.Unlock()
			deliverIPPacket(disp, data)
		}
	}
}

// WritePackets 把 netstack 出站 IP 包写回 wintun 发送环。
// 用独立的 tx 锁：wintun 的 Receive/Release 与 Allocate/Send 两侧各自线程安全，
// 收发分锁后可以并行，且投递回调里同步发包不会自死锁。
func (e *tunLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.Lock()
	session := e.adapter.session
	e.mu.Unlock()
	if session == 0 {
		return 0, &tcpip.ErrAborted{}
	}
	e.adapter.tx.Lock()
	defer e.adapter.tx.Unlock()
	n := 0
	for _, pkt := range pkts.AsSlice() {
		views := pkt.AsSlices()
		size := 0
		for _, v := range views {
			size += len(v)
		}
		if size == 0 {
			continue
		}
		packet, _, _ := wintunProcAllocateSendPacket.Call(session, uintptr(size))
		if packet == 0 {
			continue // 发送环满：丢包，由 TCP 重传
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(packet)), size)
		off := 0
		for _, v := range views {
			off += copy(dst[off:], v)
		}
		wintunProcSendPacket.Call(session, packet)
		n++
	}
	return n, nil
}

// bindToIfaceControl 返回把 socket 绑定到指定网卡的 ListenConfig Control
// （IP_UNICAST_IF，网络字节序的接口索引）
func bindToIfaceControl(ifIdx uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], ifIdx)
			v := *(*int32)(unsafe.Pointer(&b[0]))
			syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31 /*IP_UNICAST_IF*/, int(v))
		})
	}
}

// configureTapAdapter 给常驻网卡配 IP/metric（幂等）。
//
// 原实现是一条 PowerShell 命令跑 4 个操作，且每次开 TUN 都执行一遍，耗时 4~5 秒
// （PowerShell 启动 + NetTCPIP 模块加载）。这正是「开 TUN 很慢」的真正来源 ——
// 自检走原生 tun2socks 路径不经过这里，所以自检数字偏乐观。
//
// 现在：metric 用 IP Helper API（一次系统调用，且值已对时直接跳过）；
// IP 地址常驻网卡配置一次后长期有效，缺失才补。
func configureTapAdapter(ifIdx uint32) error {
	ifaceRow := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: ifIdx}
	if err := windows.GetIpInterfaceEntry(&ifaceRow); err != nil {
		return fmt.Errorf("read adapter metric (ifIdx=%d): %w", ifIdx, err)
	}
	if ifaceRow.Metric != tunMetric || ifaceRow.UseAutomaticMetric != 0 || ifaceRow.NlMtu != tapMTU {
		set := ifaceRow
		set.SitePrefixLength = 0
		set.ZoneIndices = [windows.ScopeLevelCount]uint32{}
		set.UseAutomaticMetric = 0
		set.Metric = tunMetric
		set.NlMtu = tapMTU
		if r, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&set))); r != 0 {
			// API 失败退回 netsh（比 PowerShell 快一个数量级）
			out, err := runHidden("netsh", "interface", "ipv4", "set", "interface",
				fmt.Sprintf("interface=%d", ifIdx), fmt.Sprintf("metric=%d", tunMetric), fmt.Sprintf("mtu=%d", tapMTU))
			if err != nil {
				return fmt.Errorf("set adapter metric/mtu (ifIdx=%d, winerr %d): %v: %s",
					ifIdx, r, err, strings.TrimSpace(string(out)))
			}
		}
	}
	// IPv6 的 MTU 是独立属性（失败不致命：IPv6 只用于 2000::/3 防泄漏）
	row6 := windows.MibIpInterfaceRow{Family: windows.AF_INET6, InterfaceIndex: ifIdx}
	if err := windows.GetIpInterfaceEntry(&row6); err == nil && row6.NlMtu != tapMTU {
		set := row6
		set.SitePrefixLength = 0
		set.ZoneIndices = [windows.ScopeLevelCount]uint32{}
		set.NlMtu = tapMTU
		procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&set)))
	}
	return ensureTapAddrs(ifIdx)
}

// ensureTapAddrs 确保常驻网卡已配置 tunGateway/30 与 tunGateway6/126，未配置才补。
// 常驻网卡配置一次后长期有效，所以只在缺失时调用 netsh（~0.3s，远快于 PowerShell 的 5s）。
func ensureTapAddrs(ifIdx uint32) error {
	iface, err := net.InterfaceByIndex(int(ifIdx))
	if err != nil {
		return fmt.Errorf("lookup adapter ifIdx=%d: %w", ifIdx, err)
	}
	addrs, _ := iface.Addrs()
	hasV4, hasV6 := false, false
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		switch n.IP.String() {
		case tunGateway:
			hasV4 = true
		case tunGateway6:
			hasV6 = true
		}
	}
	if !hasV4 {
		out, err := runHidden("netsh", "interface", "ipv4", "set", "address",
			fmt.Sprintf("interface=%d", ifIdx), "source=static", tunGateway,
			"mask=255.255.255.252")
		if err != nil {
			return fmt.Errorf("assign adapter IPv4 (ifIdx=%d): %v: %s", ifIdx, err, strings.TrimSpace(string(out)))
		}
	}
	// IPv6 地址是 2000::/3 防泄漏路由的下一跳，缺了这条路由就写不了
	if !hasV6 {
		out, err := runHidden("netsh", "interface", "ipv6", "add", "address",
			fmt.Sprintf("interface=%d", ifIdx), tunGateway6+"/126", "store=active")
		if err != nil {
			return fmt.Errorf("assign adapter IPv6 (ifIdx=%d): %v: %s", ifIdx, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
