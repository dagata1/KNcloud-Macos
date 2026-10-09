package main

import (
	"time"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

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

func (wintunDevice) Name() string { return tunIfaceName }

func (wintunDevice) CachedIfIdx() uint32 { return knTap.ifIdx }

func (wintunDevice) Open() (uint32, error) { return knTap.ensure() }

func (wintunDevice) Configure(ifIdx uint32) error { return configureTapAdapter(ifIdx) }

func (wintunDevice) LinkMTU() uint32 { return tapMTU }

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
