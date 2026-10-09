//go:build taptest && windows

package main

// tundev_tap_taptest.go —— 仅测试构建（-tags taptest）：用已安装的 TAP-Windows V9 网卡
// （默认 "SSTAP 1"，tap0901）代替 wintun，跑同一套 gVisor 转发 / 路由 / DNS 代码。
// 生产构建不包含本文件。启用：KNCLOUD_TUN_DEVICE=tap（可选 KNCLOUD_TAP_NAME 指定网卡名）。
//
// TAP 工作在 TUN（三层）模式：TAP_WIN_IOCTL_CONFIG_TUN(本机 IP, 网段, 掩码) 后读写的是裸 IP 包，
// 驱动替网段内除本机外的地址应答 ARP。路由下一跳仍是 tunGateway（172.19.0.1），
// 所以网卡地址配成 172.19.0.2/30 —— 路由计划与生产完全一致。
// 不安装、不修改驱动；Close 把网卡恢复为打开前的 IPv4 地址并置为 Disconnected。

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	tapIoctlSetMediaStatus = 0x22<<16 | 6<<2  // TAP_WIN_IOCTL_SET_MEDIA_STATUS
	tapIoctlConfigTun      = 0x22<<16 | 10<<2 // TAP_WIN_IOCTL_CONFIG_TUN
	tapLocalIP             = "172.19.0.2"
	tapNetwork             = "172.19.0.0"
	tapNetmask             = "255.255.255.252"
	tapLinkMTU             = 1500
)

func init() {
	if strings.EqualFold(os.Getenv("KNCLOUD_TUN_DEVICE"), "tap") {
		tunDeviceOverride = func() tunDevice { return testTap }
	}
}

type tapWinDevice struct {
	mu       sync.Mutex
	name     string
	guid     string
	ifIdx    uint32
	h        windows.Handle
	origIP   string // 打开前的 IPv4 静态地址/掩码（Close 时恢复）
	origMask string
	origDHCP bool
	tx       sync.Mutex
	txEv     windows.Handle
	txOv     *windows.Overlapped
	// 诊断计数
	RxPkts, RxBytes, TxPkts, TxBytes, TxErr, RxErr, TxMax atomic.Int64
}

var testTap = &tapWinDevice{}

func (d *tapWinDevice) Name() string        { return "TAP " + d.name }
func (d *tapWinDevice) CachedIfIdx() uint32 { return d.ifIdx }
func (d *tapWinDevice) LinkMTU() uint32     { return tapLinkMTU }

func findAdapterByName(name string) (guid string, ifIdx uint32, err error) {
	var size uint32 = 16 << 10
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, aa, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return "", 0, e
		}
		for a := aa; a != nil; a = a.Next {
			if windows.UTF16PtrToString(a.FriendlyName) == name {
				return windows.BytePtrToString(a.AdapterName), a.IfIndex, nil
			}
		}
		return "", 0, fmt.Errorf("adapter %q not found", name)
	}
	return "", 0, errors.New("GetAdaptersAddresses: buffer overflow")
}

func (d *tapWinDevice) ioctl(code uint32, in []byte) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	// OVERLAPPED 与缓冲区放在堆上：异步完成时内核回写，goroutine 栈可能已被移动
	ov := &windows.Overlapped{HEvent: ev}
	io := &struct{ in, out [16]byte }{}
	copy(io.in[:], in)
	var ret uint32
	err = windows.DeviceIoControl(d.h, code, &io.in[0], uint32(len(in)), &io.out[0], uint32(len(in)), nil, ov)
	if err == nil || err == windows.ERROR_IO_PENDING {
		err = windows.GetOverlappedResult(d.h, ov, &ret, true)
	}
	return err
}

func ip4be(s string) []byte { return net.ParseIP(s).To4() }

func (d *tapWinDevice) setMedia(up bool) error {
	v := []byte{0, 0, 0, 0}
	if up {
		v[0] = 1
	}
	return d.ioctl(tapIoctlSetMediaStatus, v)
}

func (d *tapWinDevice) Open() (uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h != 0 {
		return d.ifIdx, nil
	}
	d.name = os.Getenv("KNCLOUD_TAP_NAME")
	if d.name == "" {
		d.name = nativeSSTapIface
	}
	guid, idx, err := findAdapterByName(d.name)
	if err != nil {
		return 0, err
	}
	path, _ := windows.UTF16PtrFromString(`\\.\Global\` + guid + `.tap`)
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s (%s): %w", d.name, guid, err)
	}
	d.h, d.guid, d.ifIdx = h, guid, idx
	cfg := append(append(ip4be(tapLocalIP), ip4be(tapNetwork)...), ip4be(tapNetmask)...)
	if err := d.ioctl(tapIoctlConfigTun, cfg); err != nil {
		d.closeLocked()
		return 0, fmt.Errorf("TAP CONFIG_TUN: %w", err)
	}
	if err := d.setMedia(true); err != nil {
		d.closeLocked()
		return 0, fmt.Errorf("TAP SET_MEDIA_STATUS: %w", err)
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		d.closeLocked()
		return 0, err
	}
	d.txEv = ev
	d.txOv = &windows.Overlapped{}
	return idx, nil
}

// Configure 记录原 IPv4 配置并改为 172.19.0.2/30 + fdfe:dcba:9876::1/126（与生产网卡同一 IPv6 地址，
// 让 addTunIPv6Route 走同一路径）。metric 已是 1（SSTap 安装时设置），MTU 1500 不改。
func (d *tapWinDevice) Configure(ifIdx uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.origIP == "" && !d.origDHCP {
		// 原配置以注册表为准（断开状态下网卡上可能临时挂着 169.254 自动地址）
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+d.guid, registry.QUERY_VALUE)
		if err != nil {
			return fmt.Errorf("read TAP tcpip config: %w", err)
		}
		dhcp, _, _ := k.GetIntegerValue("EnableDHCP")
		ips, _, _ := k.GetStringsValue("IPAddress")
		masks, _, _ := k.GetStringsValue("SubnetMask")
		k.Close()
		d.origDHCP = dhcp == 1
		if !d.origDHCP && len(ips) > 0 && len(masks) > 0 && ips[0] != tapLocalIP {
			d.origIP, d.origMask = ips[0], masks[0]
		}
		if !d.origDHCP && d.origIP == "" {
			return fmt.Errorf("TAP original IPv4 config unknown (ips=%v), refusing to change it", ips)
		}
	}
	if !ifaceHasAddr(ifIdx, tapLocalIP) {
		out, err := runHidden("netsh", "interface", "ipv4", "set", "address",
			fmt.Sprintf("name=%d", ifIdx), "source=static", tapLocalIP, tapNetmask)
		if err != nil {
			return fmt.Errorf("assign TAP IPv4: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if !ifaceHasAddr(ifIdx, tunGateway6) {
		runHidden("netsh", "interface", "ipv6", "add", "address",
			fmt.Sprintf("interface=%d", ifIdx), tunGateway6+"/126", "store=active")
	}
	// 等地址生效（DAD），否则紧接着写的路由可能找不到源地址
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !ifaceHasAddr(ifIdx, tapLocalIP) {
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (d *tapWinDevice) closeLocked() {
	if d.h != 0 {
		_ = d.setMedia(false)
		windows.CloseHandle(d.h)
		d.h = 0
	}
	if d.txEv != 0 {
		windows.CloseHandle(d.txEv)
		d.txEv = 0
	}
}

// Close 测试收尾：置 Disconnected、关句柄、恢复原 IPv4 地址、删掉加上的 IPv6 地址。
func (d *tapWinDevice) Close() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeLocked()
	if d.ifIdx == 0 {
		return "not opened"
	}
	idx := fmt.Sprintf("name=%d", d.ifIdx)
	var res []string
	runHidden("netsh", "interface", "ipv6", "delete", "address", fmt.Sprintf("interface=%d", d.ifIdx), tunGateway6)
	switch {
	case d.origIP != "":
		out, err := runHidden("netsh", "interface", "ipv4", "set", "address", idx, "source=static", d.origIP, d.origMask)
		res = append(res, fmt.Sprintf("restore %s/%s: %v %s", d.origIP, d.origMask, err, strings.TrimSpace(string(out))))
	case d.origDHCP:
		out, err := runHidden("netsh", "interface", "ipv4", "set", "address", idx, "source=dhcp")
		res = append(res, fmt.Sprintf("restore dhcp: %v %s", err, strings.TrimSpace(string(out))))
	}
	return strings.Join(res, "; ")
}

func (d *tapWinDevice) NewLink() stack.LinkEndpoint {
	l := &tapLinkEndpoint{dev: d, stopCh: make(chan struct{})}
	if v, err := strconv.Atoi(os.Getenv("KN_TAP_MTU")); err == nil && v >= 576 && v <= tapLinkMTU {
		l.mtu = uint32(v)
	}
	return l
}

func (d *tapWinDevice) StopLink(l stack.LinkEndpoint, wait time.Duration) bool {
	link, _ := l.(*tapLinkEndpoint)
	if link == nil {
		return true
	}
	select {
	case <-link.stopCh:
	default:
		close(link.stopCh)
	}
	done := make(chan struct{})
	go func() { link.stopped.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(wait):
		return false
	}
}

// write 一个裸 IP 包（overlapped，tx 串行）
func (d *tapWinDevice) write(b []byte) error {
	d.tx.Lock()
	defer d.tx.Unlock()
	if d.h == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	*d.txOv = windows.Overlapped{HEvent: d.txEv}
	var n uint32
	err := windows.WriteFile(d.h, b, nil, d.txOv)
	if err == nil || err == windows.ERROR_IO_PENDING {
		err = windows.GetOverlappedResult(d.h, d.txOv, &n, true)
	}
	if err != nil {
		d.TxErr.Add(1)
	} else {
		d.TxPkts.Add(1)
		d.TxBytes.Add(int64(len(b)))
		if int64(len(b)) > d.TxMax.Load() {
			d.TxMax.Store(int64(len(b)))
		}
	}
	return err
}

// ------------------------- gVisor 链路端点（TAP） -------------------------

type tapLinkEndpoint struct {
	mtu        uint32 // 0 = tapLinkMTU（KN_TAP_MTU 可覆盖，诊断用）
	dev        *tapWinDevice
	stopCh     chan struct{}
	stopped    sync.WaitGroup
	mu         sync.Mutex
	dispatcher stack.NetworkDispatcher
}

func (e *tapLinkEndpoint) MTU() uint32 {
	if e.mtu != 0 {
		return e.mtu
	}
	return tapLinkMTU
}
func (e *tapLinkEndpoint) SetMTU(uint32)                                {}
func (e *tapLinkEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *tapLinkEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *tapLinkEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *tapLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *tapLinkEndpoint) Wait()                                        {}
func (e *tapLinkEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *tapLinkEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *tapLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *tapLinkEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcher != nil
}
func (e *tapLinkEndpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
	if d != nil {
		e.stopped.Add(1)
		go e.readLoop(d)
	}
}

func (e *tapLinkEndpoint) readLoop(disp stack.NetworkDispatcher) {
	defer e.stopped.Done()
	h := e.dev.h
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(ev)
	buf := make([]byte, 65536)
	ov := &windows.Overlapped{} // 堆上：内核异步回写
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}
		*ov = windows.Overlapped{HEvent: ev}
		windows.ResetEvent(ev)
		var n uint32
		err := windows.ReadFile(h, buf, nil, ov)
		if err == nil || err == windows.ERROR_IO_PENDING {
			for {
				r, _ := windows.WaitForSingleObject(ev, 200)
				if r == windows.WAIT_OBJECT_0 {
					break
				}
				select {
				case <-e.stopCh:
					windows.CancelIoEx(h, ov)
					windows.GetOverlappedResult(h, ov, &n, true)
					return
				default:
				}
			}
			err = windows.GetOverlappedResult(h, ov, &n, false)
		}
		if err != nil {
			select {
			case <-e.stopCh:
				return
			default:
			}
			e.dev.RxErr.Add(1)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}
		e.dev.RxPkts.Add(1)
		e.dev.RxBytes.Add(int64(n))
		data := make([]byte, n)
		copy(data, buf[:n])
		deliverIPPacket(disp, data)
	}
}

func (e *tapLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
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
		b := make([]byte, 0, size)
		for _, v := range views {
			b = append(b, v...)
		}
		if err := e.dev.write(b); err != nil {
			if n == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			break
		}
		n++
	}
	return n, nil
}
