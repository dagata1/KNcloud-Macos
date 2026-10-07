package main

// tundev.go —— 虚拟网卡后端抽象。生产只有 wintun（KNcloud-TAP）；测试构建
// （-tags taptest 且 KNCLOUD_TUN_DEVICE=tap）可以换成已安装的 TAP-Windows 网卡，
// 在装不了 wintun 的机器上实测同一套 gVisor 转发、路由、DNS 代码。

import (
	"time"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type tunDevice interface {
	Name() string
	// CachedIfIdx 上次打开得到的接口索引（未打开为 0），仅用于预校验时排除自身。
	CachedIfIdx() uint32
	// Open 打开（必要时创建）网卡，返回接口索引。幂等。
	Open() (uint32, error)
	// Configure 配置地址/metric/MTU（幂等）。
	Configure(ifIdx uint32) error
	// LinkMTU gVisor 链路 MTU。
	LinkMTU() uint32
	// NewLink 新建一个读写该网卡的 gVisor 链路端点（每次启动转发一个）。
	NewLink() stack.LinkEndpoint
	// StopLink 停止链路端点的读协程，最多等 wait；返回是否按时退出。网卡本身保留。
	StopLink(link stack.LinkEndpoint, wait time.Duration) bool
}

// tunDeviceOverride 测试构建注入的替代后端（生产构建恒为 nil）。
var tunDeviceOverride func() tunDevice

func currentTunDevice() tunDevice {
	if tunDeviceOverride != nil {
		if d := tunDeviceOverride(); d != nil {
			return d
		}
	}
	return wintunDevice{}
}

// wintunDevice 生产后端：常驻 wintun 网卡 knTap。
type wintunDevice struct{}

func (wintunDevice) Name() string                 { return tunIfaceName }
func (wintunDevice) CachedIfIdx() uint32          { return knTap.ifIdx }
func (wintunDevice) Open() (uint32, error)        { return knTap.ensure() }
func (wintunDevice) Configure(ifIdx uint32) error { return configureTapAdapter(ifIdx) }
func (wintunDevice) LinkMTU() uint32              { return tapMTU }
func (wintunDevice) NewLink() stack.LinkEndpoint {
	return &tunLinkEndpoint{
		mtu:     tapMTU,
		adapter: knTap,
		readEvt: knTap.readEvt,
		stopCh:  make(chan struct{}),
	}
}

// StopLink 先停 readLoop（唤醒读事件）。读环与协议栈解耦后 readLoop 不再持锁投递，不会卡死。
func (wintunDevice) StopLink(l stack.LinkEndpoint, wait time.Duration) bool {
	link, _ := l.(*tunLinkEndpoint)
	if link == nil {
		return true
	}
	select {
	case <-link.stopCh:
	default:
		close(link.stopCh)
	}
	if knTap.readEvt != 0 {
		_ = windows.SetEvent(knTap.readEvt)
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
