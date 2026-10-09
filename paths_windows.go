package main

import "os"

// portableModeSupported Windows 支持绿色版（exe 目录可写时数据放在 exe 旁边）。
const portableModeSupported = true

// platformResourceDirs Windows 没有额外的资源目录（bin\ 与 exe 目录由 resourceSearchDirs 处理）。
func platformResourceDirs() []string { return nil }

// userConfigBaseDir %APPDATA%（os.UserConfigDir）。
func userConfigBaseDir() (string, error) { return os.UserConfigDir() }
