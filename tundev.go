package main

// tundev.go —— 虚拟网卡后端抽象。生产只有 wintun（KNcloud-TAP）；测试构建
// （-tags taptest 且 KNCLOUD_TUN_DEVICE=tap）可以换成已安装的 TAP-Windows 网卡，
// 在装不了 wintun 的机器上实测同一套 gVisor 转发、路由、DNS 代码。

import (
	"time"

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
