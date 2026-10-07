package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAuthTokenNotExposedToFrontend 保证登录凭证不会随 AccountInfo 下发到 WebView。
//
// AccountInfo 会被 Wails 绑定原样返回给前端（GetAccount / Login / RefreshAccount），
// 而前端从不使用 authToken —— 把它打进 WebView 只是平白扩大泄露面。
// 该字段因此标记为 json:"-"。
func TestAuthTokenNotExposedToFrontend(t *testing.T) {
	acct := AccountInfo{
		LoggedIn:  true,
		Email:     "user@example.com",
		Domain:    kncloudDefaultDomain,
		AuthToken: "super-secret-token-value",
	}
	data, err := json.Marshal(acct)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "super-secret-token-value") {
		t.Fatalf("auth token leaked into the frontend payload: %s", data)
	}
	if strings.Contains(strings.ToLower(string(data)), "authtoken") {
		t.Fatalf("authToken key still present in the frontend payload: %s", data)
	}
	// 其余字段必须照常下发
	if !strings.Contains(string(data), "user@example.com") {
		t.Fatalf("expected email to survive serialization: %s", data)
	}
}

// TestAuthTokenSurvivesPersistRoundTrip 凭证不下发前端，但必须照常存盘，
// 否则用户每次重启都要重新登录。
func TestAuthTokenSurvivesPersistRoundTrip(t *testing.T) {
	cfg := persistedConfig{
		Account:      &AccountInfo{LoggedIn: true, Email: "u@e.com", AuthToken: "tok-123"},
		AccountToken: "tok-123",
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back persistedConfig
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.AccountToken != "tok-123" {
		t.Fatalf("token lost in persistence round-trip: %q", back.AccountToken)
	}
}

// TestLegacyAccountTokenMigration 旧配置把 token 存在 account.authToken 内；
// 升级后必须还能读出来，否则老用户被迫重新登录。
func TestLegacyAccountTokenMigration(t *testing.T) {
	legacy := []byte(`{
	  "settings": {"socksPort": 10808},
	  "account": {"loggedIn": true, "email": "old@user.com", "authToken": "legacy-tok"}
	}`)
	if got := legacyAccountToken(legacy); got != "legacy-tok" {
		t.Fatalf("legacy token not recovered, got %q", got)
	}
	// 新格式里 account 内已无该字段，应安全返回空串
	if got := legacyAccountToken([]byte(`{"account":{"email":"a@b.c"}}`)); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
	if got := legacyAccountToken([]byte(`not json`)); got != "" {
		t.Fatalf("expected empty string on malformed input, got %q", got)
	}
}
