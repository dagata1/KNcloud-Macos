package main

import (
	"errors"
	"testing"
	"time"
)

func switchTestApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("APPDATA", t.TempDir()) // savePersisted 写到临时目录，不碰真实配置
	return &App{
		nodes: []NodeItem{
			{ID: "a", Name: "A", Protocol: "Shadowsocks", Address: "127.0.0.1", Port: 1, Active: true},
			{ID: "b", Name: "B", Protocol: "Shadowsocks", Address: "127.0.0.1", Port: 2},
			{ID: "c", Name: "C", Protocol: "Shadowsocks", Address: "127.0.0.1", Port: 3},
		},
		activeNodeID: "a",
	}
}

type selRes struct {
	n   NodeItem
	err error
	at  time.Time
}

func goSelect(a *App, id string) chan selRes {
	ch := make(chan selRes, 1)
	go func() {
		n, err := a.SelectNode(id)
		ch <- selRes{n, err, time.Now()}
	}()
	return ch
}

// 长操作占着 a.mu 时连点两个节点：旧请求必须立即放弃（不等锁），新请求在锁释放后生效。
func TestSelectNodeSupersededWhileBusy(t *testing.T) {
	a := switchTestApp(t)
	a.mu.Lock() // 模拟卡住的长操作

	r1 := goSelect(a, "b")
	time.Sleep(100 * time.Millisecond)
	r2 := goSelect(a, "c")

	select {
	case r := <-r1:
		if !errors.Is(r.err, errSwitchSuperseded) {
			t.Fatalf("first request: want errSwitchSuperseded, got %v", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request still waiting for the lock after being superseded")
	}

	time.Sleep(100 * time.Millisecond)
	a.mu.Unlock()

	select {
	case r := <-r2:
		if r.err != nil {
			t.Fatalf("second request failed: %v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second request did not complete after the lock was released")
	}
	nodes := a.GetNodes()
	for _, n := range nodes {
		if n.Active != (n.ID == "c") {
			t.Fatalf("node %s active=%v, want only c active", n.ID, n.Active)
		}
	}
	if a.activeNodeID != "c" {
		t.Fatalf("activeNodeID = %q, want c", a.activeNodeID)
	}
}

// 锁一直拿不到时，换节点在上限内返回超时错误，选择保持不变。
func TestSelectNodeTimesOutInsteadOfHanging(t *testing.T) {
	a := switchTestApp(t)
	a.mu.Lock()
	defer a.mu.Unlock()

	start := time.Now()
	r := goSelect(a, "b")
	select {
	case res := <-r:
		if res.err == nil || errors.Is(res.err, errSwitchSuperseded) {
			t.Fatalf("want timeout error, got %v", res.err)
		}
		if el := res.at.Sub(start); el < nodeSwitchLockWait-time.Second {
			t.Fatalf("returned too early (%v)", el)
		}
	case <-time.After(nodeSwitchLockWait + 5*time.Second):
		t.Fatal("SelectNode hung past its lock wait budget")
	}
	if a.activeNodeID != "a" || !a.nodes[0].Active {
		t.Fatal("selection changed although the switch timed out")
	}
}

// 未被占锁时正常切换（无内核：只改选择）。
func TestSelectNodeImmediate(t *testing.T) {
	a := switchTestApp(t)
	if _, err := a.SelectNode("b"); err != nil {
		t.Fatal(err)
	}
	if a.activeNodeID != "b" || !a.nodes[1].Active || a.nodes[0].Active {
		t.Fatalf("unexpected selection: %+v", a.nodes)
	}
}

// 退出清理在 a.mu 被永久占用时也必须有上限地返回（托盘「退出」不能没反应）。
func TestShutdownBoundedWhenStateLockHeld(t *testing.T) {
	a := switchTestApp(t)
	a.mu.Lock() // 永不释放
	start := time.Now()
	done := make(chan struct{})
	go func() {
		a.shutdown(500 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown blocked on a.mu")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("shutdown took %v", el)
	}
	// 只执行一次
	a.shutdown(time.Second)
}

// beforeClose / appCtx 不得碰 a.mu（原生关闭时跑在 UI 线程上）。
func TestBeforeCloseDoesNotTakeStateLock(t *testing.T) {
	a := switchTestApp(t)
	a.minimizeToTray.Store(false)
	a.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		_ = a.appCtx()
		done <- a.beforeClose(nil)
	}()
	select {
	case prevent := <-done:
		if prevent {
			t.Fatal("beforeClose prevented close although minimize-to-tray is off")
		}
	case <-time.After(shutdownBudget + 3*time.Second):
		t.Fatal("beforeClose blocked on a.mu")
	}
}

func TestDedupeNodeIDs(t *testing.T) {
	a := &App{nodes: []NodeItem{
		{ID: "x", Name: "1"},
		{ID: "x", Name: "2", Active: true},
		{ID: "", Name: "3"},
		{ID: "y", Name: "4"},
		{ID: "x", Name: "5"},
	}, activeNodeID: "x"}
	if n := a.dedupeNodeIDsLocked(); n != 3 {
		t.Fatalf("fixed %d, want 3", n)
	}
	seen := map[string]bool{}
	active := 0
	for _, n := range a.nodes {
		if n.ID == "" || seen[n.ID] {
			t.Fatalf("duplicate/empty id after dedupe: %+v", a.nodes)
		}
		seen[n.ID] = true
		if n.Active {
			active++
		}
	}
	if a.nodes[0].ID != "x" || !a.nodes[0].Active || active != 1 {
		t.Fatalf("active node not kept on the first x: %+v", a.nodes)
	}
}

func TestNewNodeIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		id := newNodeID()
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}
