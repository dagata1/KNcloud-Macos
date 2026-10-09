//go:build darwin

package main

// tray_darwin.go —— macOS 上「托盘」的替代：Dock 图标 + 顶部菜单栏的应用菜单。
//
// 为什么不用菜单栏状态图标（NSStatusItem）：energye/systray 在 macOS 上要自己跑
// [NSApp run] 并占用主线程，与 Wails v2 的主循环冲突（两者都要求主线程，同时运行会崩溃
// 或其中一方收不到事件）；Wails v2 本身不提供状态栏图标 API（v3 才有）。
// 因此 macOS 版保留 Dock 图标，把 Windows 托盘右键菜单的全部功能放进应用菜单
// （「代理」菜单：更新订阅、四种模式、切换节点、重启内核），点关闭按钮隐藏应用、
// 点 Dock 图标恢复，Cmd+Q / Dock「退出」真正退出并还原系统代理。

import (
	"fmt"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const trayMaxNodeItems = 30

type trayController struct {
	app *App

	mu        sync.Mutex
	started   bool
	rebuildCh chan struct{}
}

var tray = &trayController{rebuildCh: make(chan struct{}, 1)}

// startTray 启动菜单重建循环（OnStartup 中调用，此时 Wails 运行时已就绪）。
func startTray(app *App) {
	tray.mu.Lock()
	tray.app = app
	if tray.started {
		tray.mu.Unlock()
		return
	}
	tray.started = true
	tray.mu.Unlock()
	go func() {
		for range tray.rebuildCh {
			time.Sleep(120 * time.Millisecond)
			select {
			case <-tray.rebuildCh:
			default:
			}
			tray.apply()
		}
	}()
	tray.requestRebuild()
}

// available 恒为 false：macOS 上没有托盘图标，beforeClose（Cmd+Q、Dock 退出、注销）总是真正退出；
// 标题栏关闭按钮的「隐藏到后台」由 windowCloseRequested 单独处理。
func (t *trayController) available() bool { return false }

// requestRebuild 请求按当前状态重建应用菜单（合并短时间内的多次请求）。
func (t *trayController) requestRebuild() {
	select {
	case t.rebuildCh <- struct{}{}:
	default:
	}
}

func stopTray() {}

func (t *trayController) apply() {
	a := t.app
	if a == nil {
		return
	}
	ctx := a.appCtx()
	if ctx == nil || a.quitting.Load() {
		return
	}
	wailsruntime.MenuSetApplicationMenu(ctx, buildAppMenu(a))
	wailsruntime.MenuUpdateApplicationMenu(ctx)
}

// buildAppMenu 按当前应用状态整棵构建应用菜单（与 Windows 托盘菜单项一一对应）。
func buildAppMenu(a *App) *menu.Menu {
	a.mu.RLock()
	coreRunning := a.coreRunning
	tunRunning := a.tunRunning
	routingMode := a.routingMode
	activeNodeID := a.activeNodeID
	nodes := make([]NodeItem, len(a.nodes))
	copy(nodes, a.nodes)
	a.mu.RUnlock()

	root := menu.NewMenu()

	// ---------- 应用菜单：系统标准项（关于 / 服务 / 隐藏 / 退出 Cmd+Q）。退出走 beforeClose，
	// macOS 上 tray.available() 为 false，因此总是真正退出并还原系统代理。
	root.Append(menu.AppMenu())

	// 编辑菜单：WebView 里的输入框需要它才能用 Cmd+C / Cmd+V / Cmd+A
	root.Append(menu.EditMenu())

	// ---------- 代理菜单（对应 Windows 托盘右键菜单） ----------
	pm := root.AddSubmenu("代理")
	status := "未连接"
	modeLabel := map[string]string{"bypass-cn": "绕过大陆", "global": "全局代理", "direct": "全局直连"}[routingMode]
	if modeLabel == "" {
		modeLabel = "绕过大陆"
	}
	if tunRunning {
		modeLabel = "TUN 模式"
	}
	if tunRunning || coreRunning {
		status = modeLabel
		for i := range nodes {
			if nodes[i].Active {
				status += " - " + truncateRunes(nodes[i].Name, 40)
				break
			}
		}
	}
	pm.AddText("状态："+status, nil, nil).Disable()
	pm.AddText("显示主界面", keys.CmdOrCtrl("1"), func(*menu.CallbackData) { a.showApp() })
	pm.AddSeparator()

	subLabel := "更新订阅"
	if a.traySubUpdating.Load() {
		subLabel = "正在更新订阅…"
	}
	sub := pm.AddText(subLabel, keys.CmdOrCtrl("u"), func(*menu.CallbackData) { go a.trayUpdateSubscription() })
	if a.traySubUpdating.Load() {
		sub.Disable()
	}
	pm.AddSeparator()

	for _, m := range []struct{ id, label string }{
		{"bypass-cn", "绕过大陆"},
		{"global", "全局代理"},
		{"direct", "全局直连"},
	} {
		modeID := m.id
		pm.AddCheckbox(m.label, !tunRunning && routingMode == m.id, nil, func(*menu.CallbackData) { go a.traySetRoutingMode(modeID) })
	}
	pm.AddCheckbox("TUN 模式（需管理员授权）", tunRunning, nil, func(*menu.CallbackData) { go a.traySetTun() })
	pm.AddSeparator()

	nm := pm.AddSubmenu("切换节点")
	if len(nodes) == 0 {
		nm.AddText("暂无可用节点", nil, nil).Disable()
	} else {
		limit := len(nodes)
		if limit > trayMaxNodeItems {
			limit = trayMaxNodeItems
		}
		for i := 0; i < limit; i++ {
			n := nodes[i]
			label := fmt.Sprintf("%s · %s", n.Protocol, truncateRunes(n.Name, 30))
			switch {
			case n.Delay > 0:
				label = fmt.Sprintf("%s  (%dms)", label, n.Delay)
			case n.Delay == -2:
				label += "  (超时)"
			}
			nodeID := n.ID
			nm.AddCheckbox(label, n.Active || n.ID == activeNodeID, nil, func(*menu.CallbackData) { go a.traySelectNode(nodeID) })
		}
		if len(nodes) > limit {
			nm.AddText(fmt.Sprintf("更多节点…（共 %d 个）", len(nodes)), nil, func(*menu.CallbackData) { a.showApp() })
		}
	}
	pm.AddSeparator()
	coreLabel := "重启内核"
	if !coreRunning {
		coreLabel = "重启内核（内核未运行）"
	}
	pm.AddText(coreLabel, keys.CmdOrCtrl("r"), func(*menu.CallbackData) { go a.trayRestartCore() })

	root.Append(menu.WindowMenu())
	return root
}
