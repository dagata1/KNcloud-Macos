package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// webLoginTimeout 等待网页授权回调的最长时间，超时自动关闭本地回调服务
const webLoginTimeout = 5 * time.Minute

// 网页授权流程（与 Android 端 WEB_AUTH_INTEGRATION.md 同源，回调方式不同）：
//  1. 客户端在 127.0.0.1 随机端口起一个一次性 HTTP 回调服务
//  2. 打开系统浏览器访问 官网/#/login?from=win_auth&callback=http://127.0.0.1:{port}/auth/callback
//  3. 用户在网页完成登录并授权后，网页重定向到 callback 并带上 token（auth_data）与 email
//  4. 客户端收到回调即完成登录、拉取订阅，并通过 Wails 事件通知前端刷新界面
//
// 前端事件：
//   - "kncloud:web-login"       携带 AccountInfo，登录成功
//   - "kncloud:web-login-error" 携带错误信息（超时 / 回调失败 / 换订阅失败）

type webLoginResult struct {
	token string
	email string
}

type webLoginManager struct {
	mu   sync.Mutex
	ln   net.Listener
	srv  *http.Server
	done chan *webLoginResult
}

func (m *webLoginManager) stopLocked() {
	if m.srv != nil {
		_ = m.srv.Close()
	}
	if m.ln != nil {
		_ = m.ln.Close()
	}
	m.srv = nil
	m.ln = nil
	m.done = nil
}

// StartWebLogin 打开浏览器进行网页登录授权，返回本次打开的授权 URL。
// 结果通过事件 kncloud:web-login / kncloud:web-login-error 异步通知前端。
func (a *App) StartWebLogin() (string, error) {
	a.mu.RLock()
	domain := a.account.Domain
	a.mu.RUnlock()
	if domain == "" {
		domain = kncloudDefaultDomain
	}

	m := a.webLogin
	m.mu.Lock()
	m.stopLocked() // 重复点击时先关掉上一次的回调服务

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		m.mu.Unlock()
		return "", fmt.Errorf("failed to start local callback server: %v", err)
	}
	resCh := make(chan *webLoginResult, 1)
	port := ln.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		token := q.Get("token")
		if token == "" {
			token = q.Get("auth_data")
		}
		email := q.Get("email")
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(webLoginHTML("授权失败：回调中缺少 token 参数，请重试")))
			return
		}
		select {
		case resCh <- &webLoginResult{token: token, email: email}:
		default:
		}
		_, _ = w.Write([]byte(webLoginHTML("登录成功！请回到 KNcloud-WIN 客户端继续使用，本页面可以关闭。")))
	})
	srv := &http.Server{Handler: mux}
	m.ln = ln
	m.srv = srv
	m.done = resCh
	m.mu.Unlock()

	go func() { _ = srv.Serve(ln) }()

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/auth/callback", port)
	loginURL := strings.TrimRight(domain, "/") + "/#/login?from=win_auth&callback=" + url.QueryEscape(callbackURL)

	if err := openInDefaultBrowser(loginURL); err != nil {
		a.stopWebLogin()
		return "", fmt.Errorf("failed to open browser: %v", err)
	}
	a.addLogInternal("info", fmt.Sprintf("Web login started, waiting for callback on 127.0.0.1:%d", port))

	go func() {
		var res *webLoginResult
		select {
		case res = <-resCh:
		case <-time.After(webLoginTimeout):
			res = nil
		}
		a.stopWebLogin()

		ctx := a.appCtx()
		if res == nil {
			a.addLogInternal("warn", "Web login timed out waiting for browser callback")
			if ctx != nil {
				runtime.EventsEmit(ctx, "kncloud:web-login-error", "等待网页授权超时，请重试")
			}
			return
		}
		email := strings.TrimSpace(res.email)
		if email == "" {
			email = "web-login"
		}
		acct, err := a.completeLogin(domain, email, res.token)
		if err != nil {
			a.addLogInternal("error", fmt.Sprintf("Web login failed: %v", err))
			if ctx != nil {
				runtime.EventsEmit(ctx, "kncloud:web-login-error", err.Error())
			}
			return
		}
		a.addLogInternal("info", fmt.Sprintf("Web login succeeded for %s", acct.Email))
		if ctx != nil {
			runtime.EventsEmit(ctx, "kncloud:web-login", acct)
		}
	}()

	return loginURL, nil
}

// CancelWebLogin 主动取消网页登录等待，关闭本地回调服务
func (a *App) CancelWebLogin() {
	a.stopWebLogin()
}

func (a *App) stopWebLogin() {
	m := a.webLogin
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func openInDefaultBrowser(rawURL string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
}

// webLoginHTML 回调落地页：告知用户授权结果并引导返回客户端
func webLoginHTML(msg string) string {
	return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>KNcloud-WIN 授权</title></head>` +
		`<body style="display:flex;align-items:center;justify-content:center;height:100vh;margin:0;` +
		`font-family:system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;background:#181818;color:#fff;">` +
		`<div style="text-align:center;"><div style="font-size:20px;font-weight:600;margin-bottom:12px;">KNcloud-WIN</div>` +
		`<div style="font-size:14px;opacity:.8;">` + msg + `</div></div></body></html>`
}
