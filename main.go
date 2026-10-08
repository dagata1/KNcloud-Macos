package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	// 隐藏自检入口：KNcloud-WIN.exe --tun-selftest（需管理员），验证简易模式 SSTap 链路
	if len(os.Args) > 1 && os.Args[1] == "--tun-selftest" {
		os.Exit(runTunSelfTest(app))
	}

	// 根据持久化设置确定初始窗口尺寸，避免启动时先闪一下大窗口再缩小
	// （窗口默认按 classic 尺寸创建，简易模式/登录页会先显示大窗口再缩小）
	width, height := 1120, 760
	if !app.account.LoggedIn || app.settings.UiMode == "simple" {
		width, height = 420, 640
	}

	// 未运行时由 kncloud:// 协议直接启动：窗口就绪后处理链接
	if link := findDeepLinkArg(os.Args[1:]); link != "" {
		go app.handleDeepLink(link)
	}

	err := wails.Run(&options.App{
		Title:     "KNcloud-WIN",
		Width:     width,
		Height:    height,
		MinWidth:  380, // 简易模式需要缩到紧凑尺寸（前端切换模式时自动调整）
		MinHeight: 560,
		Frameless: true, // 自定义 Win11 沉浸式标题栏
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 243, G: 243, B: 243, A: 0}, // 透明底色配合 Mica
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		// 托盘常驻后台：用户重复双击图标时唤出已运行实例，
		// 而不是启动第二个进程去抢系统代理与 10808/10809 端口。
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "KNcloud-WIN-win11-single-instance",
			OnSecondInstanceLaunch: func(d options.SecondInstanceData) {
				// 网页「一键订阅」拉起的第二个进程会把 kncloud:// 链接带过来
				if link := findDeepLinkArg(d.Args); link != "" {
					go app.handleDeepLink(link)
					return
				}
				go app.focusFromSecondInstance()
			},
		},
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              true,
			WindowIsTranslucent:               true,
			BackdropType:                      windows.Mica, // Windows 11 云母材质！
			Theme:                             windows.SystemDefault,
			DisableFramelessWindowDecorations: false, // 保留 Windows 11 原生圆角与阴影
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
