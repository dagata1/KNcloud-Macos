package main

// traffic.go —— 仪表盘流量统计（实时上传/下载、累计上行/下行）。
//
// 只统计「经代理节点」的流量：读 Xray 的 proxy 出站计数器
// （outbound>>>proxy>>>traffic>>>uplink/downlink）。该计数器包在 proxy 出站拨出的
// 连接上（含 mux 子连接所在的底层连接），即发往节点 / 从节点收到的字节：
//   - 直连（绕过大陆、全局直连、局域网）走 direct 出站，不计入；
//   - 回环跳（TUN → 127.0.0.1 SOCKS、浏览器 → 127.0.0.1 HTTP）是入站，不计入；
//   - 系统代理与 TUN 两种模式都走同一个 Xray 实例的同一个出站，口径一致。
//
// 旧实现的问题：系统代理下读的是入站计数（直连流量也算进去）；TUN 下改读虚拟网卡的
// 接口计数（含 DNS 劫持等全部包，TAP-Windows 网卡的 In/Out 方向还与本机视角相反），
// 两个来源切换时「当前值 < 上次值」被当成计数器重置，把网卡开机以来的总量整段加进累计。
//
// 计数器有独立的锁：开关 TUN、改路由等长操作持有 a.mu 数秒时，采样与状态查询都不被阻塞。

import (
	"sync"
	"sync/atomic"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// trafficStatsVersion 累计流量的统计口径版本。旧配置（无此字段）里的累计值按旧口径
// 计得（含直连、方向可能反了），加载时清零。
const trafficStatsVersion = 2

type trafficMeter struct {
	mu        sync.Mutex
	inst      *xcore.Instance // 上次采样的内核实例；换实例（重启内核）时计数器从 0 开始
	lastUp    int64
	lastDown  int64
	totalUp   int64
	totalDown int64
	upSpeed   int64 // 最近一个采样周期的字节数（采样周期 1s，即 B/s）
	downSpeed int64
}

// observe 记录一次采样。inst==nil 表示内核未运行：速率归零、累计不变。
// 同一实例内计数器只增不减；实例变化时以 0 为基线（新实例的计数器从 0 开始）。
func (m *trafficMeter) observe(inst *xcore.Instance, up, down int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inst == nil {
		m.inst, m.lastUp, m.lastDown = nil, 0, 0
		m.upSpeed, m.downSpeed = 0, 0
		return
	}
	if inst != m.inst {
		m.inst, m.lastUp, m.lastDown = inst, 0, 0
	}
	du, dd := up-m.lastUp, down-m.lastDown
	if du < 0 {
		du = 0
	}
	if dd < 0 {
		dd = 0
	}
	m.lastUp, m.lastDown = up, down
	m.totalUp += du
	m.totalDown += dd
	m.upSpeed, m.downSpeed = du, dd
}

func (m *trafficMeter) resetSpeed() {
	m.mu.Lock()
	m.upSpeed, m.downSpeed = 0, 0
	m.mu.Unlock()
}

func (m *trafficMeter) totals() (up, down int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalUp, m.totalDown
}

func (m *trafficMeter) setTotals(up, down int64) {
	m.mu.Lock()
	m.totalUp, m.totalDown = up, down
	m.mu.Unlock()
}

func (m *trafficMeter) snapshot() (upSpeed, downSpeed, totalUp, totalDown int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upSpeed, m.downSpeed, m.totalUp, m.totalDown
}

// statsInstHolder 当前运行的内核实例，供采样协程无锁读取（不经 a.mu）。
type statsInstHolder struct {
	p atomic.Pointer[xcore.Instance]
}

func (h *statsInstHolder) set(inst *xcore.Instance) { h.p.Store(inst) }
func (h *statsInstHolder) get() *xcore.Instance     { return h.p.Load() }

// proxyOutboundTraffic 读取实例上 proxy 出站的累计字节（发往节点 / 来自节点）。
func proxyOutboundTraffic(inst *xcore.Instance) (up, down int64, ok bool) {
	if inst == nil {
		return 0, 0, false
	}
	feat := inst.GetFeature(stats.ManagerType())
	if feat == nil {
		return 0, 0, false
	}
	mgr, isMgr := feat.(stats.Manager)
	if !isMgr {
		return 0, 0, false
	}
	if c := mgr.GetCounter("outbound>>>" + proxyOutboundTag + ">>>traffic>>>uplink"); c != nil {
		up = c.Value()
	}
	if c := mgr.GetCounter("outbound>>>" + proxyOutboundTag + ">>>traffic>>>downlink"); c != nil {
		down = c.Value()
	}
	return up, down, true
}

// sampleTraffic 采样一次（每秒由 startup 的协程调用）。不取 a.mu。
func (a *App) sampleTraffic() {
	inst := a.statsInst.get()
	up, down, ok := proxyOutboundTraffic(inst)
	if !ok {
		inst = nil
	}
	a.traffic.observe(inst, up, down)
}
