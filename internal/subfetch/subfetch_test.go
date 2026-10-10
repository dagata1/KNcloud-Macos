package subfetch

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func portOf(t *testing.T, addr string) int {
	_, ps, _ := net.SplitHostPort(addr)
	p, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// 假的本地 HTTP 代理：记录命中次数并回固定内容（不真正转发）。
func fakeProxy(hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if r.Header.Get("User-Agent") != UserAgent {
			http.Error(w, "bad ua", 400)
			return
		}
		w.Write([]byte("via-proxy"))
	}))
}

func TestFetchGoesThroughLocalProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("direct")) }))
	defer origin.Close()
	var hits int32
	proxy := fakeProxy(&hits)
	defer proxy.Close()
	port := portOf(t, proxy.Listener.Addr().String())

	got, err := Fetch(origin.URL, Options{Port: func() int { return port }, Wait: time.Second, Timeout: 5 * time.Second})
	if err != nil || got != "via-proxy" || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("want via proxy, got %q err=%v hits=%d", got, err, hits)
	}
}

func TestFetchNoDirectFallback(t *testing.T) {
	var originHits int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&originHits, 1)
		w.Write([]byte("direct"))
	}))
	defer origin.Close()

	// 内核没在运行（端口 0）：等满 Wait 后报错，绝不直连
	start := time.Now()
	_, err := Fetch(origin.URL, Options{Port: func() int { return 0 }, Wait: 300 * time.Millisecond, Poll: 50 * time.Millisecond, Timeout: time.Second})
	if !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("want ErrProxyUnavailable, got %v", err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatalf("returned before the wait elapsed")
	}

	// 端口给了但没人监听：同样报错、不直连
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := portOf(t, ln.Addr().String())
	ln.Close()
	_, err = Fetch(origin.URL, Options{Port: func() int { return dead }, Wait: 200 * time.Millisecond, Poll: 50 * time.Millisecond, Timeout: time.Second})
	if !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("dead port: want ErrProxyUnavailable, got %v", err)
	}
	if n := atomic.LoadInt32(&originHits); n != 0 {
		t.Fatalf("origin was contacted directly %d time(s)", n)
	}
}

// 内核正在重启：端口过一会儿才起来（而且换了端口），等到后照常走代理。
func TestFetchWaitsForRestartingCore(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("direct")) }))
	defer origin.Close()
	var hits int32
	proxy := fakeProxy(&hits)
	defer proxy.Close()
	port := portOf(t, proxy.Listener.Addr().String())

	var live atomic.Int32
	go func() {
		time.Sleep(400 * time.Millisecond)
		live.Store(int32(port))
	}()
	start := time.Now()
	got, err := Fetch(origin.URL, Options{Port: func() int { return int(live.Load()) }, Wait: 5 * time.Second, Poll: 50 * time.Millisecond, Timeout: 5 * time.Second})
	if err != nil || got != "via-proxy" {
		t.Fatalf("want via proxy after wait, got %q err=%v", got, err)
	}
	if d := time.Since(start); d < 350*time.Millisecond || d > 4*time.Second {
		t.Fatalf("unexpected wait %s", d)
	}
}

func TestFetchHTTPError(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 502) }))
	defer proxy.Close()
	port := portOf(t, proxy.Listener.Addr().String())
	if _, err := Fetch("http://example.invalid/sub", Options{Port: func() int { return port }, Wait: time.Second, Timeout: 2 * time.Second}); err == nil {
		t.Fatal("want error on HTTP 502")
	}
}
