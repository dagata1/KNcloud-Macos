package main

import (
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

// waitForParentExit 处理 --wait-pid <pid>：最多等 20 秒让该进程退出。
func waitForParentExit(args []string) {
	for i := 1; i+1 < len(args); i++ {
		if args[i] != "--wait-pid" {
			continue
		}
		pid, err := strconv.Atoi(args[i+1])
		if err != nil || pid <= 0 {
			return
		}
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
		if err != nil {
			return // 已经退出
		}
		windows.WaitForSingleObject(h, uint32((20 * time.Second).Milliseconds()))
		windows.CloseHandle(h)
		return
	}
}
