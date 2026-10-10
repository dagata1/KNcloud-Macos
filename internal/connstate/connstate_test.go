package connstate

import (
	"testing"
	"time"
)

func TestNormalizeLegacyDefaultsToProxy(t *testing.T) {
	for _, in := range []string{"", "garbage", "PROXY"} {
		if Normalize(in) != Proxy {
			t.Errorf("Normalize(%q) = %q", in, Normalize(in))
		}
	}
	for _, in := range []string{Off, Core, Proxy, Tun} {
		if Normalize(in) != in {
			t.Errorf("Normalize(%q) changed", in)
		}
	}
}

func TestPlanFor(t *testing.T) {
	cases := map[string]Plan{
		"":    {StartCore: true, SystemProxy: true},
		Proxy: {StartCore: true, SystemProxy: true},
		Core:  {StartCore: true},
		Tun:   {StartCore: true, SystemProxy: true, Tun: true},
		Off:   {StartCore: true}, // 内核常开：旧版本记下的「断开」也启动内核，只是不开系统代理
	}
	for in, want := range cases {
		if got := PlanFor(in); got != want {
			t.Errorf("PlanFor(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestCurrent(t *testing.T) {
	cases := []struct {
		name string
		prev string
		s    Snapshot
		want string
	}{
		{"tun running", Proxy, Snapshot{TunRunning: true, CoreRunning: true}, Tun},
		{"tun restore pending keeps intent", Tun, Snapshot{TunWanted: true, CoreRunning: true, SystemProxy: true}, Tun},
		{"proxy", Off, Snapshot{CoreRunning: true, SystemProxy: true}, Proxy},
		{"proxy pending counts as proxy", Off, Snapshot{CoreRunning: true, SysProxyPending: true}, Proxy},
		{"core only", Proxy, Snapshot{CoreRunning: true}, Core},
		{"user stopped core", Proxy, Snapshot{}, Off},
		{"core failed keeps previous", Proxy, Snapshot{CoreFailed: true, SysProxyPending: true}, Proxy},
		{"core failed keeps tun", Tun, Snapshot{CoreFailed: true}, Tun},
		{"core failed legacy empty", "", Snapshot{CoreFailed: true}, Proxy},
	}
	for _, c := range cases {
		if got := Current(c.prev, c.s); got != c.want {
			t.Errorf("%s: Current = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSchedules(t *testing.T) {
	if TunRestoreSchedule[0] != 0 {
		t.Error("first TUN restore attempt should be immediate")
	}
	if tot := Total(TunRestoreSchedule); tot < 3*time.Minute || tot > 10*time.Minute {
		t.Errorf("TUN restore window %s out of expected range", tot)
	}
	if tot := Total(BootCoreRetrySchedule); tot < 2*time.Minute {
		t.Errorf("boot core retry window %s too short", tot)
	}
	for i := 1; i < len(TunRestoreSchedule); i++ {
		if TunRestoreSchedule[i] < TunRestoreSchedule[i-1] {
			t.Error("TUN restore schedule should not shrink")
		}
	}
}

func TestCoreRetryWait(t *testing.T) {
	sched := []time.Duration{time.Second, 2 * time.Second}
	if w, ok := CoreRetryWait(sched, 0, true); !ok || w != time.Second {
		t.Fatalf("i=0: %v %v", w, ok)
	}
	if w, ok := CoreRetryWait(sched, 1, false); !ok || w != 2*time.Second {
		t.Fatalf("i=1: %v %v", w, ok)
	}
	// 内核完全没起来：表用完后一直重试
	for _, i := range []int{2, 3, 100} {
		if w, ok := CoreRetryWait(sched, i, true); !ok || w != SteadyCoreRetry {
			t.Fatalf("down i=%d: %v %v", i, w, ok)
		}
	}
	// 已以直连兜底运行：表用完就停
	if _, ok := CoreRetryWait(sched, 2, false); ok {
		t.Fatal("fallback running: retries must stop after the schedule")
	}
}
