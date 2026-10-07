package main

import "testing"

// 长操作持有写锁时，状态轮询返回快照而不是排队等锁。
func TestGetCoreStatusDoesNotBlockOnLongOps(t *testing.T) {
	a := &App{routingMode: "global"}
	_ = a.GetCoreStatus() // 建立快照
	a.mu.Lock()
	done := make(chan CoreStatus, 1)
	go func() { done <- a.GetCoreStatus() }()
	st := <-done
	a.mu.Unlock()
	if !st.Busy || st.RoutingMode != "global" {
		t.Fatalf("status during long op: %+v", st)
	}
}
