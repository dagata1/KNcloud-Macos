package main

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestLooksLikePortInUse(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&portInUseError{name: "HTTP", port: 10809}, true},
		{fmt.Errorf("start: %w", &portInUseError{name: "SOCKS5", port: 1}), true},
		{fmt.Errorf("%w (x)", errPortInUse), true},
		{errors.New("listen tcp 127.0.0.1:10809: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted."), true},
		{errors.New("listen tcp 127.0.0.1:1: bind: An attempt was made to access a socket in a way forbidden by its access permissions."), true},
		{errors.New("failed to build core config: unknown cipher"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := looksLikePortInUse(c.err); got != c.want {
			t.Errorf("looksLikePortInUse(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func withFastBackoff(t *testing.T) {
	old := coreRetryBackoff
	coreRetryBackoff = []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
	t.Cleanup(func() { coreRetryBackoff = old })
}

// 没有节点 → 每次启动都失败（非端口错误）：重试三次后停在 failed，不再重试。
func TestCoreRetryLoopGivesUpAfterBackoff(t *testing.T) {
	withFastBackoff(t)
	t.Setenv("APPDATA", t.TempDir())
	a := &App{}
	a.mu.Lock()
	a.handleCoreStartFailureLocked(errors.New("boom"), false)
	if !a.coreRetrying {
		a.mu.Unlock()
		t.Fatal("non-port failure should schedule retries")
	}
	a.mu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for {
		st := a.GetCoreStatus()
		if st.CoreState == "failed" {
			if st.CoreError == "" {
				t.Fatal("failed state without a reason")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry loop did not finish, state=%s", st.CoreState)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 端口占用不自动重试，状态直接是 failed + CorePortError。
func TestCorePortErrorDoesNotRetry(t *testing.T) {
	a := &App{}
	a.mu.Lock()
	a.handleCoreStartFailureLocked(&portInUseError{name: "HTTP", port: 10809}, false)
	a.mu.Unlock()
	st := a.GetCoreStatus()
	if st.CoreState != "failed" || !st.CorePortError {
		t.Fatalf("want failed+port error, got %+v", st)
	}
}

// 取消（换节点 / 手动操作 / 退出）后，正在等待的重试不再执行。
func TestCoreRetryLoopCanceled(t *testing.T) {
	old := coreRetryBackoff
	coreRetryBackoff = []time.Duration{300 * time.Millisecond, 300 * time.Millisecond, 300 * time.Millisecond}
	t.Cleanup(func() { coreRetryBackoff = old })
	a := &App{}
	a.mu.Lock()
	a.coreRetrying = true
	a.mu.Unlock()
	gen := a.coreRetryGen.Add(1)
	done := make(chan struct{})
	go func() { a.coreRetryLoop(gen); close(done) }()
	time.Sleep(50 * time.Millisecond)
	a.coreRetryGen.Add(1) // 取消
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop ignored cancellation")
	}
	if a.coreErr != "" {
		t.Fatalf("canceled loop still attempted a start: %q", a.coreErr)
	}
}

// 重启内核失败（无节点）时返回错误并进入自动重试；锁不会被留着。
func TestRestartCoreFailureSchedulesRetry(t *testing.T) {
	withFastBackoff(t)
	t.Setenv("APPDATA", t.TempDir())
	a := &App{}
	if _, err := a.RestartCore(); err == nil {
		t.Fatal("want error with no node selected")
	}
	if !a.mu.TryLock() {
		t.Fatal("RestartCore left a.mu locked")
	}
	a.mu.Unlock()
	a.coreRetryGen.Add(1) // 结束后台重试
}
