package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName = "KNcloud-WIN"
	// legacyRunValueName 是改名前用的自启项名。改名后旧条目仍指向旧的 exe 路径，
	// 会在任务管理器里留下一条永远启动失败的死项，所以写新值时顺手清掉。
	legacyRunValueName = "KNcloud"
)

var errNoExecutablePath = errors.New("cannot resolve current executable path")

// currentExecutablePath 返回当前进程的可执行文件绝对路径（解析软链接后）。
func currentExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if exe == "" {
		return "", errNoExecutablePath
	}
	return exe, nil
}

// isAutoStartEnabled 检查当前用户登录自启项是否已指向本程序。
func isAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(runValueName)
	if err != nil {
		return false
	}
	return val != ""
}

// setAutoStart 写入 / 移除 HKCU Run 自启项。返回 error 时注册表保持原样。
func setAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	// 清理改名前的自启项残留（不存在时 registry.ErrNotExist，忽略即可）。
	if err := k.DeleteValue(legacyRunValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}

	if enable {
		exe, err := currentExecutablePath()
		if err != nil {
			return err
		}
		return k.SetStringValue(runValueName, `"`+exe+`"`)
	}

	if err := k.DeleteValue(runValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
