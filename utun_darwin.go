//go:build darwin

package main

// utun_darwin.go —— macOS 虚拟网卡（utun）后端。
//
// 助手（root）创建 utun 并配置地址/MTU，再把描述符交给主程序；主程序把它包装成
// gVisor LinkEndpoint，驱动与 Windows 完全相同的 tapForwarder（tapfwd.go）。
// utun 每个包前有 4 字节协议族头（AF_INET=2 / AF_INET6=30，网络序）。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
	utunControlName = "com.apple.net.utun_control"
	tunPeerAddr     = "172.19.0.2" // utun 是点对点接口：本端 tunGateway，对端占位
)

// createUtun 创建一个新的 utunN（需要 root），返回描述符与接口名。
func createUtun() (int, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return -1, "", fmt.Errorf("socket(AF_SYSTEM): %w", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("CTLIOCGINFO: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("connect utun control: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("UTUN_OPT_IFNAME: %w", err)
	}
	unix.CloseOnExec(fd)
	return fd, strings.TrimRight(name, "\x00"), nil
}

// openUtun 助手侧：创建并配置 utun（地址 tunGateway↔tunPeerAddr、IPv6 tunGateway6/126、MTU）。
func (s *tunHelperServer) openUtun(mtu int) (int, string, int, error) {
	if mtu <= 0 {
		mtu = tapMTU
	}
	fd, name, err := createUtun()
	if err != nil {
		return -1, "", 0, err
	}
	ifconfig := func(args ...string) error {
		out, err := exec.Command("/sbin/ifconfig", append([]string{name}, args...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ifconfig %s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := ifconfig("inet", tunGateway, tunPeerAddr, "netmask", "255.255.255.252", "mtu", fmt.Sprint(mtu), "up"); err != nil {
		s.logf("%v; retrying with MTU 1500", err)
		mtu = 1500
		if err := ifconfig("inet", tunGateway, tunPeerAddr, "netmask", "255.255.255.252", "mtu", "1500", "up"); err != nil {
			unix.Close(fd)
			return -1, "", 0, err
		}
	}
	// IPv6 地址只用于 2000::/3 防泄漏路由，失败不致命
	if err := ifconfig("inet6", tunGateway6, "prefixlen", "126"); err != nil {
		s.logf("%v", err)
	}
	return fd, name, mtu, nil
}

// ------------------------- 主程序侧：常驻 utun -------------------------

// utunState 本进程持有的 utun（进程生命周期内复用；关闭描述符即销毁网卡）。
type utunState struct {
	mu    sync.Mutex
	file  *os.File
	name  string
	ifIdx uint32
	mtu   uint32
}

var knUtun = &utunState{}

// ensure 拿到 utun：没有时请助手创建并通过 SCM_RIGHTS 取回描述符（幂等）。
func (u *utunState) ensure() (uint32, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file != nil {
		if _, err := net.InterfaceByIndex(int(u.ifIdx)); err == nil {
			return u.ifIdx, nil
		}
		u.file.Close()
		u.file = nil
	}
	if err := tunHelper.ensure(); err != nil {
		return 0, err
	}
	resp, fds, err := tunHelper.call(helperReq{Op: "open_utun", MTU: tapMTU})
	if err != nil {
		return 0, err
	}
	if !resp.OK || len(fds) == 0 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		if resp.Err == "" {
			resp.Err = "helper returned no utun descriptor"
		}
		return 0, errors.New(resp.Err)
	}
	for _, extra := range fds[1:] {
		unix.Close(extra)
	}
	fd := fds[0]
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return 0, err
	}
	unix.CloseOnExec(fd)
	u.file = os.NewFile(uintptr(fd), resp.Name) // 非阻塞描述符：读写走 Go 的 kqueue 轮询器，可设超时唤醒
	u.name = resp.Name
	u.ifIdx = uint32(resp.Index)
	u.mtu = uint32(resp.MTU)
	if u.ifIdx == 0 {
		if ifc, err := net.InterfaceByName(resp.Name); err == nil {
			u.ifIdx = uint32(ifc.Index)
		}
	}
	return u.ifIdx, nil
}

func (u *utunState) snapshot() (*os.File, string, uint32, uint32) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.file, u.name, u.ifIdx, u.mtu
}

// closeDevice 关闭描述符（utun 及其上的路由随之由内核回收）。
func (u *utunState) closeDevice() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file != nil {
		u.file.Close()
		u.file = nil
	}
	u.ifIdx = 0
}

// utunDevice 实现 tunDevice（tundev.go）。
type utunDevice struct{}

func currentTunDevice() tunDevice {
	if tunDeviceOverride != nil {
		if d := tunDeviceOverride(); d != nil {
			return d
		}
	}
	return utunDevice{}
}

func (utunDevice) Name() string {
	if _, name, _, _ := knUtun.snapshot(); name != "" {
		return name
	}
	return "utun"
}
func (utunDevice) CachedIfIdx() uint32 { _, _, idx, _ := knUtun.snapshot(); return idx }
func (utunDevice) Open() (uint32, error) {
	idx, err := knUtun.ensure()
	if err == nil {
		darwinTunIfIdx.Store(idx)
	}
	return idx, err
}
func (utunDevice) Configure(ifIdx uint32) error { return nil } // 助手创建时已配好地址与 MTU
func (utunDevice) LinkMTU() uint32 {
	if _, _, _, mtu := knUtun.snapshot(); mtu > 0 {
		return mtu
	}
	return tapMTU
}
func (d utunDevice) NewLink() stack.LinkEndpoint {
	f, _, _, _ := knUtun.snapshot()
	return newUtunLinkEndpoint(f, d.LinkMTU())
}
func (utunDevice) StopLink(l stack.LinkEndpoint, wait time.Duration) bool {
	link, _ := l.(*utunLinkEndpoint)
	if link == nil {
		return true
	}
	return link.stop(wait)
}

// ------------------------- gVisor 链路端点 -------------------------

type utunLinkEndpoint struct {
	mtu        uint32
	file       *os.File
	stopCh     chan struct{}
	stopOnce   sync.Once
	dispatcher stack.NetworkDispatcher
	stopped    sync.WaitGroup
	mu         sync.Mutex
	wmu        sync.Mutex
}

func newUtunLinkEndpoint(f *os.File, mtu uint32) *utunLinkEndpoint {
	return &utunLinkEndpoint{mtu: mtu, file: f, stopCh: make(chan struct{})}
}

func (e *utunLinkEndpoint) MTU() uint32                        { return e.mtu }
func (e *utunLinkEndpoint) SetMTU(mtu uint32)                  { e.mtu = mtu }
func (e *utunLinkEndpoint) MaxHeaderLength() uint16            { return 0 }
func (e *utunLinkEndpoint) LinkAddress() tcpip.LinkAddress     { return "" }
func (e *utunLinkEndpoint) SetLinkAddress(a tcpip.LinkAddress) {}
func (e *utunLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}
func (e *utunLinkEndpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
	if d != nil && e.file != nil {
		e.stopped.Add(1)
		go e.readLoop(d)
	}
}
func (e *utunLinkEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcher != nil
}
func (e *utunLinkEndpoint) Wait() {}
func (e *utunLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}
func (e *utunLinkEndpoint) AddHeader(*stack.PacketBuffer)        {}
func (e *utunLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (e *utunLinkEndpoint) isStopped() bool {
	select {
	case <-e.stopCh:
		return true
	default:
		return false
	}
}

// readLoop 从 utun 读包（去掉 4 字节协议族头）投递给协议栈。
// stop 通过 SetReadDeadline 唤醒阻塞的 Read，描述符本身保留给下一个链路端点复用。
func (e *utunLinkEndpoint) readLoop(d stack.NetworkDispatcher) {
	defer e.stopped.Done()
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("[utun] readLoop panic recovered:", r)
		}
	}()
	buf := make([]byte, int(e.mtu)+4+64)
	for {
		if e.isStopped() {
			return
		}
		n, err := e.file.Read(buf)
		if err != nil {
			if e.isStopped() {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n <= 4 {
			continue
		}
		data := make([]byte, n-4)
		copy(data, buf[4:n])
		deliverIPPacket(d, data)
	}
}

// WritePackets 把协议栈的出站 IP 包加上协议族头写回 utun（每次 write 一个完整包）。
func (e *utunLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e.file == nil {
		return 0, &tcpip.ErrAborted{}
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
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
		b := make([]byte, 4+size)
		off := 4
		for _, v := range views {
			off += copy(b[off:], v)
		}
		switch b[4] >> 4 {
		case 4:
			binary.BigEndian.PutUint32(b[:4], unix.AF_INET)
		case 6:
			binary.BigEndian.PutUint32(b[:4], unix.AF_INET6)
		default:
			continue
		}
		if _, err := e.file.Write(b); err != nil {
			continue // 写失败丢包，由 TCP 重传
		}
		n++
	}
	return n, nil
}

func (e *utunLinkEndpoint) stop(wait time.Duration) bool {
	e.stopOnce.Do(func() { close(e.stopCh) })
	if e.file != nil {
		_ = e.file.SetReadDeadline(time.Now())
	}
	done := make(chan struct{})
	go func() { e.stopped.Wait(); close(done) }()
	ok := true
	select {
	case <-done:
	case <-time.After(wait):
		ok = false
	}
	if ok && e.file != nil {
		_ = e.file.SetReadDeadline(time.Time{})
	}
	return ok
}
