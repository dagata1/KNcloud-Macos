package main

import goruntime "runtime"

// GetPlatform 当前操作系统（"windows" / "darwin"），供前端按平台隐藏不适用的选项与文案。
func (a *App) GetPlatform() string { return goruntime.GOOS }
