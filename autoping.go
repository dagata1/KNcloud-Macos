package main

import (
	"fmt"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// autoPinger 后台自动测速（启动、订阅更新后、仪表盘刷新按钮）。
//
// 同一时间只跑一轮；进行中再次请求只记一个 pending，本轮结束后补跑一轮
// （例如测速途中订阅刷新换了节点列表），不会叠加出多轮并发测速。
type autoPinger struct {
	mu      sync.Mutex
	running bool
	pending bool
}

// autoPingStateEvent 自动测速开始/结束时推给前端的事件：{"running": bool}。
// 单个节点的结果沿用 PingNode 的 kncloud:node-delay 事件，边测边显示。
const autoPingStateEvent = "kncloud:auto-ping"

// requestAutoPing 请求一轮后台全量测速，立即返回。
//
// 只在 Wails 运行时（a.ctx 非空）生效：单测里刷新订阅不会真的去连节点。
// 测速用独立的临时 Xray 实例，不碰主内核出站、系统代理与 TUN 路由；
// TUN 开启时测速出站绑物理网卡（见 realDelayTestConfig）。
func (a *App) requestAutoPing() {
	if a.ctx == nil {
		return
	}
	a.autoPing.mu.Lock()
	if a.autoPing.running {
		a.autoPing.pending = true
		a.autoPing.mu.Unlock()
		return
	}
	a.autoPing.running = true
	a.autoPing.mu.Unlock()

	go func() {
		for {
			a.emitAutoPingState(true)
			a.autoPingRound()

			a.autoPing.mu.Lock()
			if !a.autoPing.pending {
				a.autoPing.running = false
				a.autoPing.mu.Unlock()
				a.emitAutoPingState(false)
				return
			}
			a.autoPing.pending = false
			a.autoPing.mu.Unlock()
		}
	}()
}

func (a *App) autoPingRound() {
	nodes := a.GetNodes()
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	if len(ids) == 0 {
		return
	}
	ok := a.pingIDs(ids, true)
	a.addLogInternal("info", fmt.Sprintf("Auto latency test finished: %d/%d nodes reachable", ok, len(ids)))
}

func (a *App) emitAutoPingState(running bool) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, autoPingStateEvent, map[string]interface{}{"running": running})
	}
}

// StartAutoPing 前端「重新测速」按钮：在后台测速全部节点，立即返回。
// 结果通过 kncloud:node-delay 逐个推送，开始/结束通过 kncloud:auto-ping 推送。
func (a *App) StartAutoPing() {
	a.requestAutoPing()
}

// IsAutoPinging 前端加载时查询后台测速是否进行中（错过了开始事件时用）。
func (a *App) IsAutoPinging() bool {
	a.autoPing.mu.Lock()
	defer a.autoPing.mu.Unlock()
	return a.autoPing.running
}
