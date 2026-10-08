package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// 网页「一键订阅 → KNcloud For Windows」与安卓端同源：浏览器打开
//   kncloud://login?token=<auth_data>&email=<email>&domain=<官网>&sub_url=<订阅地址>
// 由系统按 HKCU\Software\Classes\kncloud 拉起本程序（deeplink_windows.go 注册），
// 已在运行时经单实例锁把参数转给主实例。
//
// 安全：任意网页都能构造这种链接，所以
//   1. domain 只接受 https 的 kncloud.top / *.kncloud.top，或当前账户已在用的官网；
//   2. 登录前弹系统对话框让用户确认账户与官网；
//   3. sub_url 不直接使用，订阅地址一律用 token 向官网重新获取（completeLogin）。

const deepLinkScheme = "kncloud"

type deepLinkLogin struct {
	Token  string
	Email  string
	Domain string
}

// findDeepLinkArg 从命令行参数里找出 kncloud:// 链接（协议启动时它是唯一参数）。
func findDeepLinkArg(args []string) string {
	for _, a := range args {
		a = strings.Trim(strings.TrimSpace(a), `"`)
		if strings.HasPrefix(strings.ToLower(a), deepLinkScheme+"://") {
			return a
		}
	}
	return ""
}

// normalizeHTTPSOrigin 把官网地址规整成 https://host，拒绝 http、带账号、带路径的地址。
func normalizeHTTPSOrigin(raw string) (string, bool) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil {
		return "", false
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return "https://" + strings.ToLower(u.Host), true
}

// isTrustedDomain 官网是否可信：kncloud.top 及其子域名，或与当前账户官网完全一致。
func isTrustedDomain(origin, current string) bool {
	o, ok := normalizeHTTPSOrigin(origin)
	if !ok {
		return false
	}
	host := strings.TrimPrefix(o, "https://")
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}
	if host == "kncloud.top" || strings.HasSuffix(host, ".kncloud.top") {
		return true
	}
	if c, ok := normalizeHTTPSOrigin(current); ok && c == o {
		return true
	}
	return false
}

// parseDeepLink 解析 kncloud://login?... ；不可信或缺字段时返回错误。
func parseDeepLink(raw, currentDomain string) (deepLinkLogin, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, deepLinkScheme) {
		return deepLinkLogin{}, fmt.Errorf("无效的链接")
	}
	action := strings.ToLower(u.Host)
	if action == "" {
		action = strings.ToLower(strings.Trim(u.Opaque+u.Path, "/"))
	}
	if action != "login" {
		return deepLinkLogin{}, fmt.Errorf("不支持的链接类型：%s", action)
	}
	q := u.Query()
	token := strings.TrimSpace(q.Get("token"))
	if token == "" {
		token = strings.TrimSpace(q.Get("auth_data"))
	}
	if token == "" {
		return deepLinkLogin{}, fmt.Errorf("链接缺少登录凭证")
	}
	domain := q.Get("domain")
	if domain == "" {
		domain = currentDomain
	}
	if domain == "" {
		domain = kncloudDefaultDomain
	}
	origin, ok := normalizeHTTPSOrigin(domain)
	if !ok || !isTrustedDomain(origin, currentDomain) {
		return deepLinkLogin{}, fmt.Errorf("不受信任的官网地址：%s", domain)
	}
	return deepLinkLogin{Token: token, Email: strings.TrimSpace(q.Get("email")), Domain: origin}, nil
}

// handleDeepLink 处理一次 kncloud:// 启动：校验 → 用户确认 → 用 token 登录并同步订阅。
func (a *App) handleDeepLink(raw string) {
	for i := 0; i < 100 && a.appCtx() == nil; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	ctx := a.appCtx()
	if ctx == nil {
		return
	}
	a.showMainWindow()

	a.mu.RLock()
	current := a.account.Domain
	a.mu.RUnlock()

	link, err := parseDeepLink(raw, current)
	if err != nil {
		a.addLogInternal("warn", fmt.Sprintf("Ignored kncloud:// link: %v", err))
		runtime.EventsEmit(ctx, "kncloud:web-login-error", err.Error())
		return
	}

	who := link.Email
	if who == "" {
		who = "网页中已登录的账户"
	}
	answer, err := runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
		Type:          runtime.QuestionDialog,
		Title:         "导入 KNcloud 订阅",
		Message:       fmt.Sprintf("是否使用 %s 登录 KNcloud-WIN 并导入订阅？\n\n官网：%s", who, link.Domain),
		Buttons:       []string{"Yes", "No"},
		DefaultButton: "Yes",
		CancelButton:  "No",
	})
	if err != nil || (answer != "Yes" && answer != "是") {
		a.addLogInternal("info", "kncloud:// login cancelled by user")
		return
	}

	acct, err := a.completeLogin(link.Domain, link.Email, link.Token)
	if err != nil {
		a.addLogInternal("error", fmt.Sprintf("kncloud:// login failed: %v", err))
		runtime.EventsEmit(ctx, "kncloud:web-login-error", err.Error())
		return
	}
	a.addLogInternal("info", fmt.Sprintf("kncloud:// login succeeded for %s", acct.Email))
	runtime.EventsEmit(ctx, "kncloud:web-login", acct)
}
