package updfetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"v2rayN-win11/internal/subfetch"
)

func portOf(t *testing.T, s *httptest.Server) int {
	t.Helper()
	_, ps, _ := net.SplitHostPort(s.Listener.Addr().String())
	p, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// 假的本地 HTTP 代理：收到的是代理形式的请求（绝对 URL），记录命中、回 body。
func fakeProxy(hits *int32, body string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", 400)
			return
		}
		if r.Header.Get("User-Agent") != "KNcloud-WIN/test" {
			http.Error(w, "bad ua", 400)
			return
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func countingOrigin(hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Write([]byte("direct"))
	}))
}

func opts(port func() int, wait time.Duration) subfetch.Options {
	return subfetch.Options{Port: port, Wait: wait, Poll: 20 * time.Millisecond, Timeout: 5 * time.Second}
}

func TestGetViaLocalProxyOnly(t *testing.T) {
	var oh, ph int32
	origin := countingOrigin(&oh)
	defer origin.Close()
	proxy := fakeProxy(&ph, `{"tag_name":"v9.9.9"}`, 200)
	defer proxy.Close()
	port := portOf(t, proxy)

	data, err := Get(Request{URL: origin.URL + "/releases/latest", UserAgent: "KNcloud-WIN/test", Accept: "application/vnd.github+json", MaxBytes: 1 << 20},
		opts(func() int { return port }, time.Second))
	if err != nil || string(data) != `{"tag_name":"v9.9.9"}` {
		t.Fatalf("got %q err=%v", data, err)
	}
	if ph != 1 || oh != 0 {
		t.Fatalf("proxy hits=%d origin hits=%d, want 1/0", ph, oh)
	}
}

func TestGetNoDirectFallbackWhenCoreDown(t *testing.T) {
	var oh int32
	origin := countingOrigin(&oh)
	defer origin.Close()
	start := time.Now()
	_, err := Get(Request{URL: origin.URL, UserAgent: "KNcloud-WIN/test", MaxBytes: 1024}, opts(func() int { return 0 }, 200*time.Millisecond))
	if !errors.Is(err, subfetch.ErrProxyUnavailable) {
		t.Fatalf("want ErrProxyUnavailable, got %v", err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("did not wait for the core")
	}
	if oh != 0 {
		t.Fatal("origin contacted directly")
	}
}

// 本地代理请求失败（例如代理回 502）不会退回直连。
func TestGetProxyErrorNoDirectFallback(t *testing.T) {
	var oh, ph int32
	origin := countingOrigin(&oh)
	defer origin.Close()
	proxy := fakeProxy(&ph, "bad gateway", 502)
	defer proxy.Close()
	port := portOf(t, proxy)
	_, err := Get(Request{URL: origin.URL, UserAgent: "KNcloud-WIN/test", MaxBytes: 1024}, opts(func() int { return port }, time.Second))
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.Code != 502 {
		t.Fatalf("want HTTP 502, got %v", err)
	}
	if oh != 0 {
		t.Fatal("origin contacted directly after proxy failure")
	}
}

// 内核重启中：端口先是 0，过一会儿以新端口起来 —— 等它并用新端口。
func TestGetWaitsForRestartAndFollowsNewPort(t *testing.T) {
	var ph int32
	proxy := fakeProxy(&ph, "ok", 200)
	defer proxy.Close()
	newPort := portOf(t, proxy)
	var cur atomic.Int32
	time.AfterFunc(150*time.Millisecond, func() { cur.Store(int32(newPort)) })
	data, err := Get(Request{URL: "http://example.invalid/x", UserAgent: "KNcloud-WIN/test", MaxBytes: 1024},
		opts(func() int { return int(cur.Load()) }, 3*time.Second))
	if err != nil || string(data) != "ok" || ph != 1 {
		t.Fatalf("got %q err=%v hits=%d", data, err, ph)
	}
}

// 两次请求之间端口被自动换掉：第二次请求用新端口。
func TestPortReReadPerRequest(t *testing.T) {
	var h1, h2 int32
	p1s := fakeProxy(&h1, "one", 200)
	defer p1s.Close()
	p2s := fakeProxy(&h2, "two", 200)
	defer p2s.Close()
	var cur atomic.Int32
	cur.Store(int32(portOf(t, p1s)))
	o := opts(func() int { return int(cur.Load()) }, time.Second)
	r := Request{URL: "http://example.invalid/x", UserAgent: "KNcloud-WIN/test", MaxBytes: 1024}
	if d, err := Get(r, o); err != nil || string(d) != "one" {
		t.Fatalf("first: %q %v", d, err)
	}
	cur.Store(int32(portOf(t, p2s)))
	if d, err := Get(r, o); err != nil || string(d) != "two" {
		t.Fatalf("second: %q %v", d, err)
	}
	if h1 != 1 || h2 != 1 {
		t.Fatalf("hits %d/%d", h1, h2)
	}
}

func TestDownloadViaProxyHashAndProgress(t *testing.T) {
	var oh, ph int32
	origin := countingOrigin(&oh)
	defer origin.Close()
	body := strings.Repeat("KNcloud", 50000)
	proxy := fakeProxy(&ph, body, 200)
	defer proxy.Close()
	port := portOf(t, proxy)
	dst := filepath.Join(t.TempDir(), "x.zip")
	last := -1
	sum, err := Download(Request{URL: origin.URL + "/x.zip", UserAgent: "KNcloud-WIN/test", MaxBytes: 10 << 20}, dst, int64(len(body)),
		opts(func() int { return port }, time.Second), func(p int) { last = p })
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(body))
	if sum != hex.EncodeToString(want[:]) {
		t.Fatal("sha256 mismatch")
	}
	if got, _ := os.ReadFile(dst); string(got) != body {
		t.Fatal("file content mismatch")
	}
	if last != 100 || ph != 1 || oh != 0 {
		t.Fatalf("progress=%d proxy=%d origin=%d", last, ph, oh)
	}
}

func TestDownloadCoreDownRemovesNothingAndNoDirect(t *testing.T) {
	var oh int32
	origin := countingOrigin(&oh)
	defer origin.Close()
	dst := filepath.Join(t.TempDir(), "x.zip")
	_, err := Download(Request{URL: origin.URL, UserAgent: "KNcloud-WIN/test", MaxBytes: 1024}, dst, 0, opts(func() int { return 0 }, 100*time.Millisecond), nil)
	if !errors.Is(err, subfetch.ErrProxyUnavailable) || oh != 0 {
		t.Fatalf("err=%v origin=%d", err, oh)
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Fatal("partial file left behind")
	}
}

func TestDownloadTooLargeRemovesFile(t *testing.T) {
	var ph int32
	proxy := fakeProxy(&ph, strings.Repeat("x", 4096), 200)
	defer proxy.Close()
	port := portOf(t, proxy)
	dst := filepath.Join(t.TempDir(), "x.zip")
	_, err := Download(Request{URL: "http://example.invalid/x", UserAgent: "KNcloud-WIN/test", MaxBytes: 1024}, dst, 0, opts(func() int { return port }, time.Second), nil)
	var tl *ErrTooLarge
	if !errors.As(err, &tl) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Fatal("oversized file left behind")
	}
}
