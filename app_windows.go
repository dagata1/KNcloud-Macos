package main

import "github.com/wailsapp/wails/v2/pkg/runtime"

// cutConnsOnRoutingSwitch Windows 保持 #13：换策略只影响新连接，已建立的连接保持原出口（与 v2rayN 一致）。
const cutConnsOnRoutingSwitch = false

// defaultTheme Windows 版界面主题默认值（保持原来的深色）。
const defaultTheme = "dark"

// windowCloseRequested 标题栏关闭按钮：交给 Wails 退出流程，由 beforeClose 决定收进托盘还是退出。
func (a *App) windowCloseRequested() {
	if ctx := a.appCtx(); ctx != nil {
		runtime.Quit(ctx)
	}
}
