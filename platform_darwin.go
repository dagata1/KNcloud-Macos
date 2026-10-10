//go:build darwin

package main

import (
	"errors"
	"os/exec"
	"strconv"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/unix"
)

// cutConnsOnRoutingSwitch 切换分流模式时是否切断按旧策略建立的连接。macOS 上浏览器复用
// 长连接，不切断的话刷新页面不生效，必须重启浏览器。
const cutConnsOnRoutingSwitch = true

// defaultTheme 界面主题默认值：macOS 跟随系统浅色/深色外观。
const defaultTheme = "system"

// updateRepo macOS 版在线更新查询的 GitHub 仓库。
const updateRepo = "dagata1/KNcloud-macOS"

// releaseZipName macOS 发布包（ditto 打包的 KNcloud.app，universal 二进制）。
func releaseZipName(tag string) string { return "KNcloud-macOS-" + tag + ".zip" }

// openInDefaultBrowser 用系统默认浏览器打开链接。
func openInDefaultBrowser(rawURL string) error {
	return exec.Command("/usr/bin/open", rawURL).Start()
}

// waitForParentExit 处理 --wait-pid <pid>：最多等 20 秒让该进程退出（更新后重启用）。
func waitForParentExit(args []string) {
	for i := 1; i+1 < len(args); i++ {
		if args[i] != "--wait-pid" {
			continue
		}
		pid, err := strconv.Atoi(args[i+1])
		if err != nil || pid <= 1 {
			return
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		return
	}
}

// windowCloseRequested 标题栏关闭按钮：开启「最小化到后台」时隐藏应用（点 Dock 图标即可恢复），
// 否则真正退出。Cmd+Q、Dock「退出」、注销关机走 beforeClose，始终退出（tray.available() 为 false）。
func (a *App) windowCloseRequested() {
	if a.minimizeToTray.Load() && !a.quitting.Load() {
		if ctx := a.appCtx(); ctx != nil {
			runtime.Hide(ctx)
			a.addLogInternal("info", "Window hidden; click the Dock icon or use the menu bar to show it again")
			return
		}
	}
	go a.quitApp()
}

// showApp 取消隐藏并把主窗口拉到前台（菜单「显示主界面」、Dock、深链接）。
func (a *App) showApp() {
	if ctx := a.appCtx(); ctx != nil {
		runtime.Show(ctx)
	}
	a.showMainWindow()
}
