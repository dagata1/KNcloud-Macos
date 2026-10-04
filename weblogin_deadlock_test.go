package main

// 回归测试：cleanup() 曾持有 a.mu 时调用 stopWebLogin()（内部再次 a.mu.Lock()），
// 而 sync.RWMutex 不可重入 —— 退出时必然死锁。此测试直接调用 cleanup() 并要求
// 在超时内返回。修复前必挂（超时失败），修复后正常返回。

import (
	"testing"
	"time"
)

func TestCleanupDoesNotDeadlock(t *testing.T) {
	app := NewApp()
	app.webLogin = &webLoginManager{} // 让 stopWebLogin 有事可做

	done := make(chan struct{})
	go func() {
		app.cleanup()
		close(done)
	}()

	select {
	case <-done:
		// 正常返回即证明未死锁
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup() deadlocked: still holding a.mu while calling stopWebLogin()")
	}
}