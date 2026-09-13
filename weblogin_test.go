package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestWebLoginCallback 验证网页授权回传链路：StartWebLogin 起本地回调服务 →
// 模拟网页授权后重定向（GET /auth/callback?token=..&email=..）→
// completeLogin 被触发（token 无效时记录失败日志，不落地登录态）。
func TestWebLoginCallback(t *testing.T) {
	app := NewApp()

	if _, err := app.StartWebLogin(); err != nil {
		t.Fatalf("StartWebLogin failed: %v", err)
	}
	defer app.stopWebLogin()

	// 从日志里取本地回调端口
	var port string
	for i := 0; i < 20 && port == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		for _, l := range app.GetLogs() {
			if m := regexp.MustCompile(`127\.0\.0\.1:(\d+)`).FindStringSubmatch(l.Message); m != nil {
				port = m[1]
				break
			}
		}
	}
	if port == "" {
		t.Fatal("callback server did not start (no port in logs)")
	}

	// 模拟网页授权后的重定向
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/auth/callback?token=fake-token&email=test@example.com", port))
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("callback HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "KNcloud-WIN") {
		t.Fatalf("unexpected callback page: %s", body)
	}

	// fake token 无法换取订阅：completeLogin 应失败并留下错误日志
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range app.GetLogs() {
			if l.Level == "error" && strings.Contains(l.Message, "Web login failed") {
				return // 链路走通
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("expected 'Web login failed' log entry after invalid-token callback")
}

// TestWebLoginMissingToken 缺少 token 参数时回调应返回 400
func TestWebLoginMissingToken(t *testing.T) {
	app := NewApp()
	if _, err := app.StartWebLogin(); err != nil {
		t.Fatalf("StartWebLogin failed: %v", err)
	}
	defer app.stopWebLogin()

	var port string
	for i := 0; i < 20 && port == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		for _, l := range app.GetLogs() {
			if m := regexp.MustCompile(`127\.0\.0\.1:(\d+)`).FindStringSubmatch(l.Message); m != nil {
				port = m[1]
				break
			}
		}
	}
	if port == "" {
		t.Fatal("callback server did not start")
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/auth/callback?email=test@example.com", port))
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected HTTP 400 for missing token, got %d", resp.StatusCode)
	}
}
