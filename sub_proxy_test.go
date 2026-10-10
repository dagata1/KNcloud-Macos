package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"v2rayN-win11/internal/subfetch"
)

// 订阅一律经本地 HTTP 代理（真实内核，直连配置）；内核没在运行时等一会儿后报错，不直连。
func TestSubscriptionFetchAlwaysViaLocalProxy(t *testing.T) {
	var hits int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte("sub-content"))
	}))
	defer origin.Close()

	old := subProxyWait
	subProxyWait = 500 * time.Millisecond
	t.Cleanup(func() { subProxyWait = old })

	a := newTestApp(t)
	// 内核没在运行：报错，源站一次都没被直连
	if _, err := a.fetchSubscriptionContent(origin.URL); !errors.Is(err, subfetch.ErrProxyUnavailable) {
		t.Fatalf("core not running: want ErrProxyUnavailable, got %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("origin contacted directly while the core was down")
	}

	// 内核（无节点 → 直连配置）起来后经本地代理拉取
	a.mu.Lock()
	if err := a.startCoreLocked(); err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	a.coreRunning = true
	a.mu.Unlock()
	got, err := a.fetchSubscriptionContent(origin.URL)
	if err != nil || got != "sub-content" || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("via local proxy: got %q err=%v hits=%d", got, err, hits)
	}
}

// 应用内更新（检查更新 / 下载 .sha256 / 下载 zip）与订阅一样只经本地 HTTP 代理，不看路由模式、不直连兜底。
func TestUpdateRequestsAlwaysViaLocalProxy(t *testing.T) {
	var hits int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.URL.Path {
		case "/latest":
			w.Write([]byte(`{"tag_name":"v9.9.9","assets":[]}`))
		default:
			w.Write([]byte("payload"))
		}
	}))
	defer origin.Close()

	oldWait, oldAPI := subProxyWait, updateLatestAPI
	subProxyWait = 500 * time.Millisecond
	updateLatestAPI = origin.URL + "/latest"
	t.Cleanup(func() { subProxyWait, updateLatestAPI = oldWait, oldAPI })

	a := newTestApp(t)
	a.routingMode = "direct" // 即使是全局直连模式也走本地代理（由内核直连出站）
	dst := filepath.Join(t.TempDir(), "x.zip")
	if _, err := a.fetchLatestRelease(); err == nil {
		t.Fatal("core not running: update check should fail, not go direct")
	}
	if _, err := a.fetchSmall(origin.URL + "/x.zip.sha256"); !errors.Is(err, subfetch.ErrProxyUnavailable) {
		t.Fatalf("core not running: fetchSmall want ErrProxyUnavailable, got %v", err)
	}
	if _, err := a.downloadTo(origin.URL+"/x.zip", dst, 0, nil); !errors.Is(err, subfetch.ErrProxyUnavailable) {
		t.Fatalf("core not running: downloadTo want ErrProxyUnavailable, got %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("origin contacted directly while the core was down")
	}

	a.mu.Lock()
	if err := a.startCoreLocked(); err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	a.coreRunning = true
	a.mu.Unlock()
	rel, err := a.fetchLatestRelease()
	if err != nil || rel.TagName != "v9.9.9" {
		t.Fatalf("update check via local proxy: %+v %v", rel, err)
	}
	if d, err := a.fetchSmall(origin.URL + "/x.zip.sha256"); err != nil || string(d) != "payload" {
		t.Fatalf("fetchSmall via local proxy: %q %v", d, err)
	}
	if _, err := a.downloadTo(origin.URL+"/x.zip", dst, 0, nil); err != nil {
		t.Fatalf("downloadTo via local proxy: %v", err)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("origin hits=%d, want 3 (all via the local proxy)", hits)
	}
}
