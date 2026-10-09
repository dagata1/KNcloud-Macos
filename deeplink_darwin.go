//go:build darwin

package main

// registerURLProtocol macOS 上 kncloud:// 由 Info.plist 的 CFBundleURLTypes 声明，
// LaunchServices 在 .app 首次运行/拷贝到「应用程序」时自动登记；链接经
// options.Mac.OnUrlOpen 投递（见 main_darwin.go），无需运行时注册。
func registerURLProtocol() error { return nil }
