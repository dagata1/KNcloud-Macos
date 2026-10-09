//go:build darwin

package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var aboutIcon []byte

func main() {
	// 特权助手（由 osascript / sudo 以 root 拉起，见 tunhelper_darwin.go）：不初始化 App、不开窗口
	if len(os.Args) > 2 && os.Args[1] == "--tun-helper" {
		os.Exit(runTunHelper(os.Args[2:]))
	}
	// 隐藏自检入口（CI 冒烟用）：内嵌 Xray 起本地 SOCKS 入站并经它访问本地 HTTP 服务
	if len(os.Args) > 1 && os.Args[1] == "--core-selftest" {
		os.Exit(runCoreSelfTest())
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("KNcloud (macOS)", appVersion, "| Xray-core", xrayCoreVersion())
		os.Exit(0)
	}

	// 在线更新后由旧进程拉起：先等旧进程退出，否则单实例锁会把本进程当成「重复启动」
	waitForParentExit(os.Args)
	app := NewApp()
	if n := cleanupAfterUpdate(); n > 0 {
		app.addLogInternal("info", fmt.Sprintf("Removed %d file(s) left by the previous update", n))
	}
	app.addLogInternal("info", "KNcloud for macOS version "+appVersion)
	sysProxySocksPort.Store(int32(app.settings.SocksPort))

	width, height := 1120, 760
	if !app.account.LoggedIn || app.settings.UiMode == "simple" {
		width, height = 420, 640
	}

	if link := findDeepLinkArg(os.Args[1:]); link != "" {
		go app.handleDeepLink(link)
	}

	err := wails.Run(&options.App{
		Title:     "KNcloud",
		Width:     width,
		Height:    height,
		MinWidth:  380,
		MinHeight: 560,
		Frameless: true, // 与 Windows 版相同的自绘标题栏（最小化 / 最大化 / 关闭按钮在右上角）
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 243, G: 243, B: 243, A: 255},
		Menu:             buildAppMenu(app),
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "top.kncloud.macos.single-instance",
			OnSecondInstanceLaunch: func(d options.SecondInstanceData) {
				if link := findDeepLinkArg(d.Args); link != "" {
					go app.handleDeepLink(link)
					return
				}
				go app.showApp()
			},
		},
		Bind: []interface{}{
			app,
		},
		Mac: &mac.Options{
			Appearance:           mac.DefaultAppearance,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			About: &mac.AboutInfo{
				Title:   "KNcloud " + appVersion,
				Message: "KNcloud for macOS · 智能分流代理\nXray-core " + xrayCoreVersion(),
				Icon:    aboutIcon,
			},
			// kncloud:// 链接（Info.plist 声明的 URL scheme）：运行中或冷启动都会走这里
			OnUrlOpen: func(url string) {
				if link := findDeepLinkArg([]string{url}); link != "" {
					go app.handleDeepLink(link)
				}
				go app.showApp()
			},
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
