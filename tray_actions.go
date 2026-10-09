package main

import (
	"errors"
	"fmt"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// truncateRunes 按字符（而非字节）截断，避免把中文切成乱码。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// traySetTun 托盘「TUN 模式」：未开则开（全局接管）；已开时再点保持不变（与仪表盘一致，
// 退出 TUN 通过选择其它三个模式之一）。
func (a *App) traySetTun() {
	a.mu.RLock()
	tunRunning := a.tunRunning
	a.mu.RUnlock()
	if !tunRunning {
		if _, err := a.SimpleConnect(true); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Tray: switch to TUN mode failed: %v", err))
		}
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) traySelectNode(id string) {
	if _, err := a.SelectNode(id); err != nil && !errors.Is(err, errSwitchSuperseded) {
		a.addLogInternal("error", fmt.Sprintf("Tray: switch node failed: %v", err))
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

// trayRestartCore 托盘「重启内核」。
func (a *App) trayRestartCore() {
	if _, err := a.RestartCore(); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: restart core failed: %v", err))
		a.emitToast("重启内核失败："+err.Error(), "error")
	} else {
		a.emitToast("内核已重新启动", "success")
	}
	a.notifyFrontend()
	tray.requestRebuild()
}

func (a *App) traySetRoutingMode(mode string) {
	a.SetRoutingMode(mode)
	a.notifyFrontend()
	tray.requestRebuild()
}

// trayUpdateSubscription 托盘「更新订阅」：刷新账户信息并同步订阅节点，完成后通知界面刷新并弹出提示。
// 同一时间只跑一次；进行中菜单项显示「正在更新订阅…」并置灰。
func (a *App) trayUpdateSubscription() {
	if !a.traySubUpdating.CompareAndSwap(false, true) {
		return
	}
	tray.requestRebuild()
	defer func() {
		a.traySubUpdating.Store(false)
		a.notifyFrontend()
		tray.requestRebuild()
	}()
	_, err := a.RefreshAccount()
	if err == nil {
		err = a.SyncNodes()
	}
	ctx := a.appCtx()
	if err != nil {
		a.addLogInternal("error", fmt.Sprintf("Tray: subscription update failed: %v", err))
		if ctx != nil {
			wailsruntime.EventsEmit(ctx, "kncloud:toast", map[string]string{"msg": "更新失败：" + err.Error(), "type": "error"})
		}
		return
	}
	a.addLogInternal("info", "Tray: subscription and nodes updated")
	if ctx != nil {
		wailsruntime.EventsEmit(ctx, "kncloud:toast", map[string]string{"msg": "订阅及节点已更新", "type": "success"})
	}
}

// notifyFrontend 通知界面刷新（托盘操作可能改变了节点 / 模式 / 开关状态）。
func (a *App) notifyFrontend() {
	ctx := a.appCtx()
	if ctx == nil {
		return
	}
	wailsruntime.EventsEmit(ctx, "kncloud:refresh")
}
