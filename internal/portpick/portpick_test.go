package portpick

import (
	"net"
	"strconv"
	"testing"
)

func busySet(ports ...int) Busy {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	return func(p int) bool { return m[p] }
}

func TestPickKeepsFreePort(t *testing.T) {
	if got := Pick(10808, nil, busySet(), nil); got != 10808 {
		t.Fatalf("got %d", got)
	}
}

func TestPickMovesUpward(t *testing.T) {
	if got := Pick(10808, nil, busySet(10808, 10809, 10810), nil); got != 10811 {
		t.Fatalf("got %d, want 10811", got)
	}
}

func TestPickSkipsAvoid(t *testing.T) {
	if got := Pick(10808, map[int]bool{10808: true, 10809: true}, busySet(), nil); got != 10810 {
		t.Fatalf("got %d, want 10810", got)
	}
}

func TestPickFallsBackToSystem(t *testing.T) {
	allBusy := func(p int) bool { return p != 40000 }
	if got := Pick(65500, nil, allBusy, func() int { return 40000 }); got != 40000 {
		t.Fatalf("got %d, want 40000", got)
	}
	if got := Pick(65500, nil, func(int) bool { return true }, func() int { return 0 }); got != 0 {
		t.Fatalf("nothing free: got %d, want 0", got)
	}
}

func TestPickNeverExceeds65535(t *testing.T) {
	got := Pick(65535, nil, busySet(65535), nil)
	if got != 0 {
		t.Fatalf("got %d, want 0 (no port above 65535 and no system assign)", got)
	}
}

func TestResolvePairNoConflict(t *testing.T) {
	r := ResolvePair(10808, 10809, nil, false, false, busySet(), nil)
	if r.Changed() || r.Socks != 10808 || r.HTTP != 10809 {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestResolvePairBusySocksDoesNotCollideWithHTTP(t *testing.T) {
	// SOCKS 10808 被占，往上第一个是 10809 —— 但那是 HTTP 自己要用的端口，SOCKS 拿走后 HTTP 也要换。
	r := ResolvePair(10808, 10809, nil, false, false, busySet(10808), nil)
	if !r.OK() || r.Socks == r.HTTP {
		t.Fatalf("ports must differ: %+v", r)
	}
	if r.Socks != 10809 || r.HTTP != 10810 || !r.SocksMoved || !r.HTTPMoved {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestResolvePairBusyHTTPOnly(t *testing.T) {
	r := ResolvePair(10808, 10809, nil, false, false, busySet(10809), nil)
	if r.Socks != 10808 || r.HTTP != 10810 || r.SocksMoved || !r.HTTPMoved {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestResolvePairAvoidsReservedTunPort(t *testing.T) {
	r := ResolvePair(10808, 10809, []int{10810}, false, false, busySet(10809), nil)
	if r.HTTP != 10811 {
		t.Fatalf("HTTP must skip the reserved TUN UDP port: %+v", r)
	}
	r = ResolvePair(10810, 10809, []int{10810}, false, false, busySet(), nil)
	if r.Socks == 10810 {
		t.Fatalf("SOCKS must not take the reserved port: %+v", r)
	}
}

func TestResolvePairSamePortConfigured(t *testing.T) {
	r := ResolvePair(10808, 10808, nil, false, false, busySet(), nil)
	if r.Socks != 10808 || r.HTTP != 10809 || !r.HTTPMoved {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestResolvePairForce(t *testing.T) {
	// 预检显示空闲，但真正监听时 HTTP 端口失败：强制换掉 HTTP，SOCKS 不动
	r := ResolvePair(10808, 10809, nil, false, true, busySet(), nil)
	if r.Socks != 10808 || r.HTTP != 10810 || !r.HTTPMoved || r.SocksMoved {
		t.Fatalf("unexpected %+v", r)
	}
}

// 真实监听：另一个程序占着端口时 ListenBusy 能识别出来，并挑到一个真能监听的端口。
func TestListenBusyRealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	taken := ln.Addr().(*net.TCPAddr).Port
	busy := ListenBusy("127.0.0.1")
	if !busy(taken) {
		t.Fatalf("port %d is held by another listener but reported free", taken)
	}
	got := Pick(taken, nil, busy, SystemAssign("127.0.0.1"))
	if got == 0 || got == taken {
		t.Fatalf("expected a different free port, got %d", got)
	}
	l2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(got)))
	if err != nil {
		t.Fatalf("picked port %d is not listenable: %v", got, err)
	}
	l2.Close()
}
