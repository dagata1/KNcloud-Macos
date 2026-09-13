package main

import (
	"sync"
	"testing"
)

const (
	logTestGoroutines   = 20
	logTestPerGoroutine = 25
	logTestUnderMu      = 10
)

// 日志并发回归测试。
//
// 背景：addLogInternal 会被未持 a.mu 的 goroutine 调用（「全部测速」并发起的
// PingNode、托盘菜单动作、TUN 进程看门狗）。修复前它裸改 a.logs / a.logIDCounter，
// 并发下会丢日志、产生重复 ID。现在内部改用独立的 logMu 保护。
//
// 本机是 windows/386 且没有 C 编译器，`go test -race` 用不了，所以这里改成断言
// 「可观测的损坏」：ID 重复（计数器丢更新）与条数超上限（切片头丢更新）。
// 用同一套负载跑修复前的无锁实现，3 次里 2 次出现丢写入 + 重复 ID，说明负载够狠。
func TestLogConcurrentAppend(t *testing.T) {
	app := &App{}

	var wg sync.WaitGroup

	for i := 0; i < logTestGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < logTestPerGoroutine; j++ {
				app.addLogInternal("info", "concurrent")
			}
		}()
	}

	// 并发读：模拟前端每 2 秒轮询 GetLogs
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < logTestPerGoroutine; j++ {
				_ = app.GetLogs()
			}
		}()
	}

	// 持 a.mu 写日志：验证 a.mu -> logMu 的嵌套顺序不会死锁
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < logTestUnderMu; j++ {
			app.mu.Lock()
			app.addLogInternal("warn", "write under a.mu")
			app.mu.Unlock()
		}
	}()

	// 并发 ClearLogs
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			app.ClearLogs()
		}
	}()

	wg.Wait()

	logs := app.GetLogs()
	if len(logs) > 500 {
		t.Fatalf("log buffer exceeded its 500-entry cap: %d", len(logs))
	}

	seen := make(map[int64]bool, len(logs))
	for _, l := range logs {
		if seen[l.ID] {
			t.Fatalf("logIDCounter++ lost an update: duplicate log ID %d", l.ID)
		}
		seen[l.ID] = true
	}
	t.Logf("%d entries, all IDs unique, buffer cap respected", len(logs))
}
