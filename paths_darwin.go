//go:build darwin

package main

import (
	"os"
	"path/filepath"
)

// portableModeSupported macOS 不支持绿色版：.app 内部写入会破坏代码签名，
// 配置与日志一律放在 ~/Library/Application Support/KNcloud。
const portableModeSupported = false

// platformResourceDirs .app 的 Contents/Resources（geoip.dat / geosite.dat 由 CI 打包进去）。
func platformResourceDirs() []string {
	if d := exeDir(); d != "" {
		return []string{filepath.Join(filepath.Dir(d), "Resources")}
	}
	return nil
}

// userConfigBaseDir ~/Library/Application Support。
// go test 时沿用各测试设置的 APPDATA 作为隔离目录（单测原本就靠它避免写真实配置）。
func userConfigBaseDir() (string, error) {
	if isGoTestBinary() {
		if d := os.Getenv("APPDATA"); d != "" {
			return d, nil
		}
	}
	return os.UserConfigDir()
}
