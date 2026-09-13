package main

import (
	_ "embed"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/energye/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// trayIconData 是托盘图标：白色 KN 字标 + 全透明背景（16~256 多尺寸 ICO）。
// 不能用 build/windows/icon.ico —— 那个是应用图标，背景是不透明的黑色方块，
// 放进深色任务栏会变成一坨黑。
//
//go:embed build/windows/tray.ico
var trayIconData []byte

// trayMaxNodeItems 限制右键菜单里直接列出的节点数量，超出的引导到主界面，
// 避免节点很多时弹出菜单长到屏幕外。
const trayMaxNodeItems = 20

type trayController struct {
	app *App

	mu      sync.Mutex
	ready   bool
	pending bool // ready 之前收到的重建请求，等菜单就绪后补一次

	rebuildCh chan struct{}
}

var tray = &trayController{rebuildCh: make(chan struct{}, 1)}

// startTray 启动托盘图标。systray 自己带一个 Win32 消息循环，必须独占一个
// 锁定住的 OS 线程，因此放到独立 goroutine 里跑，不影响 Wails 主循环。
func startTray(app *App) {
	tray.app = app
	go func() {
		runtime.LockOSThread()
		systray.Run(tray.onReady, tray.onExit)
	}()
}

func (t *trayController) available() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ready
}

// requestRebuild 请求重建右键菜单。短时间内多次调用会被合并，避免菜单正被
// 用户打开时反复刷新。
func (t *trayController) requestRebuild() {
	t.mu.Lock()
	ready := t.ready
	if !ready {
		t.pending = true
	}
	t.mu.Unlock()

	if !ready {
		return
	}
	select {
	case t.rebuildCh <- struct{}{}:
	default: // 已经有待处理的请求，合并掉
	}
}

func (t *trayController) onReady() {
	systray.SetIcon(trayIconData)
	systray.SetTooltip("KNcloud-WIN · 智能分流代理")

	// 左键单击 / 双击：唤出主界面
	systray.SetOnClick(func(systray.IMenu) { t.app.showMainWindow() })
	systray.SetOnDClick(func(systray.IMenu) { t.app.showMainWindow() })
	// 右键：不注册回调，systray 默认弹出菜单

	t.mu.Lock()
	t.ready = true
	pending := t.pending
	t.pending = false
	t.mu.Unlock()

	t.buildMenu()

	// 菜单重建循环
	go func() {
		for range t.rebuildCh {
			// 合并同一批状态变更触发的多次请求
			time.Sleep(120 * time.Millisecond)
			select {
			case <-t.rebuildCh:
			default:
			}
			// 托盘已收起（用户在重建窗口期内点了「退出」）：直接结束，
			// 避免对着已销毁的窗口调 ResetMenu/AddMenuItem 刷一堆 systray error
			if !t.available() {
				return
			}
			t.buildMenu()
		}
	}()

	if pending {
		t.requestRebuild()
	}
}

func (t *trayController) onExit() {
	t.mu.Lock()
	t.ready = false
	t.mu.Unlock()
}

// stopTray 收起托盘图标（退出流程中调用）。未就绪时不做任何事，避免向空窗口句柄发消息。
func stopTray() {
	tray.mu.Lock()
	ready := tray.ready
	tray.mu.Unlock()
	if ready {
		systray.Quit()
	}
}

// buildMenu 按当前应用状态整棵重建右键菜单。
// 节点列表、分流模式、开关状态都会变化，整树重建比增量维护简单且不会残留脏项。
func (t *trayController) buildMenu() {
	// 托盘未就绪 / 已收起时直接返回：systray 的操作会失败并打印错误日志
	if !t.available() {
		return
	}

	a := t.app
	if a == nil {
		return
	}

	a.mu.RLock()
	coreRunning := a.coreRunning
	tunRunning := a.tunRunning
	routingMode := a.routingMode
	systemProxy := a.systemProxy
	activeNodeID := a.activeNodeID
	nodes := make([]NodeItem, len(a.nodes))
	copy(nodes, a.nodes)
	a.mu.RUnlock()

	autoStart := isAutoStartEnabled()

	// 当前活动节点名（仅用于悬停提示）
	activeName := ""
	for i := range nodes {
		if nodes[i].Active {
			activeName = fmt.Sprintf("%s %s", nodes[i].Protocol, truncateRunes(nodes[i].Name, 22))
			break
		}
	}

	statusText := "未连接"
	switch {
	case tunRunning:
		statusText = "TUN 全局模式运行中"
	case coreRunning:
		statusText = "代理运行中"
	}

	systray.ResetMenu()

	// 运行状态与当前节点不再占用菜单行，只留在鼠标悬停的 tooltip 里
	statusLabel := "KNcloud-WIN · " + statusText
	if activeName != "" {
		statusLabel += " · " + activeName
	}
	systray.SetTooltip(statusLabel)

	// ---------- 连接开关 ----------
	if coreRunning || tunRunning {
		miDisconnect := systray.AddMenuItem("断开连接", "停止内核与 TUN，并关闭系统代理")
		miDisconnect.Click(func() { go a.trayDisconnect() })
	} else {
		miConnect := systray.AddMenuItem("一键连接", "启动内核并开启系统代理")
		miConnect.Click(func() { go a.trayConnect() })
	}

	// ---------- 分流模式 ----------
	miRouting := systray.AddMenuItem("路由模式", "切换分流策略")
	for _, m := range []struct{ id, label string }{
		{"bypass-cn", "绕过大陆 (GFWList & CN)"},
		{"global", "全局代理"},
		{"direct", "全局直连"},
	} {
		child := miRouting.AddSubMenuItemCheckbox(m.label, "", routingMode == m.id)
		modeID := m.id
		child.Click(func() { go a.traySetRoutingMode(modeID) })
	}

	// ---------- 切换节点 ----------
	miNodes := systray.AddMenuItem("切换节点", "选择要使用的代理节点")
	switch {
	case len(nodes) == 0:
		empty := miNodes.AddSubMenuItem("暂无可用节点", "请先添加节点或同步订阅")
		empty.Disable()
	default:
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
			child := miNodes.AddSubMenuItemCheckbox(label, n.Address, n.Active || n.ID == activeNodeID)
			nodeID := n.ID
			child.Click(func() { go a.traySelectNode(nodeID) })
		}
		if len(nodes) > limit {
			more := miNodes.AddSubMenuItem(fmt.Sprintf("更多节点…（共 %d 个）", len(nodes)), "打开主界面查看完整节点列表")
			more.Click(func() { a.showMainWindow() })
		}
	}

	systray.AddSeparator()

	// ---------- 开关项 ----------
	miProxy := systray.AddMenuItemCheckbox("系统代理", "开启 / 关闭 Windows 系统代理", systemProxy)
	miProxy.Click(func() { go a.trayToggleSystemProxy() })

	miTun := systray.AddMenuItemCheckbox("TUN 全局模式", "虚拟网卡接管全部流量（需管理员权限）", tunRunning)
	miTun.Click(func() { go a.trayToggleTun() })

	miAuto := systray.AddMenuItemCheckbox("开机自启", "登录 Windows 后自动启动 KNcloud-WIN", autoStart)
	miAuto.Click(func() { go a.trayToggleAutoStart() })

	systray.AddSeparator()

	miQuit := systray.AddMenuItem("退出 KNcloud-WIN", "退出程序并还原系统代理")
	miQuit.Click(func() { go a.quitApp() })
}

// truncateRunes 按字符（而非字节）截断，避免把中文切成乱码。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// ------------------------- 托盘菜单动作 -------------------------

func (a *App) trayConnect() {
	if _, err := a.ToggleCore(true); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: start core failed: %v", err))
	} else {
		_, _ = a.ToggleSystemProxy(true)
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) trayDisconnect() {
	if _, err := a.ToggleCore(false); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: stop core failed: %v", err))
	}
	a.mu.Lock()
	if a.tunRunning {
		a.stopTunLocked()
	}
	if a.systemProxy {
		setWindowsSystemProxy(false, "")
		a.systemProxy = false
	}
	a.savePersisted()
	a.mu.Unlock()

	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) trayToggleTun() {
	a.mu.RLock()
	running := a.tunRunning
	a.mu.RUnlock()

	if _, err := a.SimpleConnect(!running); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: TUN toggle failed: %v", err))
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) traySelectNode(id string) {
	if _, err := a.SelectNode(id); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: switch node failed: %v", err))
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) traySetRoutingMode(mode string) {
	a.SetRoutingMode(mode)
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) trayToggleSystemProxy() {
	a.mu.RLock()
	current := a.systemProxy
	a.mu.RUnlock()

	if _, err := a.ToggleSystemProxy(!current); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: toggle system proxy failed: %v", err))
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) trayToggleAutoStart() {
	next := !isAutoStartEnabled()
	if err := setAutoStart(next); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: update auto-start failed: %v", err))
	} else {
		a.mu.Lock()
		a.settings.AutoStart = next
		a.savePersisted()
		a.mu.Unlock()
		if next {
			a.addLogInternal("info", "Tray: auto-start on Windows logon enabled")
		} else {
			a.addLogInternal("info", "Tray: auto-start on Windows logon disabled")
		}
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

// notifyFrontend 通知界面刷新（托盘操作可能改变了节点 / 模式 / 开关状态）。
func (a *App) notifyFrontend() {
	ctx := a.appCtx()
	if ctx == nil {
		return
	}
	wailsruntime.EventsEmit(ctx, "kncloud:refresh")
}
