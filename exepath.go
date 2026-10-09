package main

import (
	"errors"
	"os"
	"path/filepath"
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
