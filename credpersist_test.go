package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	testAuthToken = "auth-token-abcdef"
	testAcctSub   = "https://panel.example.com/api/v1/client/subscribe?token=ACCTTOKEN123"
	testListSub   = "https://panel.example.com/api/v1/client/subscribe?token=SUBTOKEN456"
)

// useTempConfigDir 把配置目录指向临时目录，避免污染真实用户配置。
func useTempConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)         // Windows：os.UserConfigDir 读取此变量
	t.Setenv("XDG_CONFIG_HOME", dir) // 其它平台
	if configFilePath() == "" {
		t.Skip("无法定位配置目录")
	}
}

func seedApp() *App {
	a := &App{}
	a.settings.SocksPort = 10808
	a.settings.HttpPort = 10809
	a.account = AccountInfo{LoggedIn: true, Email: "u@example.com",
		AuthToken: testAuthToken, SubURL: testAcctSub}
	a.subscriptions = []SubscriptionItem{
		{ID: "s1", Name: "主订阅", URL: testListSub, NodeCount: 3},
	}
	return a
}

// TestNoPlaintextCredentialsOnDisk 登录凭证、账户订阅地址、订阅列表地址
// 三者都不得以明文写入配置文件，且重新载入后必须原样可用。
func TestNoPlaintextCredentialsOnDisk(t *testing.T) {
	useTempConfigDir(t)
	seedApp().savePersisted()

	raw, err := os.ReadFile(configFilePath())
	if err != nil {
		t.Fatalf("读配置失败: %v", err)
	}
	text := string(raw)
	for name, secret := range map[string]string{
		"登录凭证":      testAuthToken,
		"账户订阅地址":    testAcctSub,
		"订阅列表地址":    testListSub,
		"token 片段A": "ACCTTOKEN123",
		"token 片段B": "SUBTOKEN456",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s 以明文出现在配置文件中", name)
		}
	}

	b := &App{}
	if !b.loadPersisted() {
		t.Fatal("重新载入失败")
	}
	if b.account.AuthToken != testAuthToken {
		t.Fatalf("凭证还原失败: %q", b.account.AuthToken)
	}
	if b.account.SubURL != testAcctSub {
		t.Fatalf("账户订阅地址还原失败: %q", b.account.SubURL)
	}
	if len(b.subscriptions) != 1 || b.subscriptions[0].URL != testListSub {
		t.Fatalf("订阅地址还原失败: %+v", b.subscriptions)
	}
}

// TestLegacyPlaintextConfigMigrates 旧版明文配置必须能读出，
// 并在下次保存时迁移为密文 —— 老用户升级后不能丢订阅、也不能被登出。
func TestLegacyPlaintextConfigMigrates(t *testing.T) {
	useTempConfigDir(t)

	legacy := map[string]interface{}{
		"settings": map[string]interface{}{"socksPort": 10808, "httpPort": 10809},
		"account": map[string]interface{}{
			"loggedIn": true, "email": "u@example.com",
			"authToken": testAuthToken, "subUrl": testAcctSub,
		},
		"subscriptions": []map[string]interface{}{
			{"id": "s1", "name": "主订阅", "url": testListSub, "nodeCount": 3},
		},
		"nodes": []interface{}{},
	}
	data, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(configFilePath(), data, 0644); err != nil {
		t.Fatalf("写旧配置失败: %v", err)
	}

	a := &App{}
	if !a.loadPersisted() {
		t.Fatal("旧配置应可载入")
	}
	if a.account.AuthToken != testAuthToken {
		t.Fatalf("旧版凭证应可读: %q", a.account.AuthToken)
	}
	if a.account.SubURL != testAcctSub {
		t.Fatalf("旧版账户订阅地址应可读: %q", a.account.SubURL)
	}
	if len(a.subscriptions) != 1 || a.subscriptions[0].URL != testListSub {
		t.Fatalf("旧版订阅地址应可读: %+v", a.subscriptions)
	}

	a.savePersisted()
	raw, _ := os.ReadFile(configFilePath())
	for _, secret := range []string{testAuthToken, testAcctSub, testListSub} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("迁移后仍残留明文: %s", secret)
		}
	}
	c := &App{}
	if !c.loadPersisted() {
		t.Fatal("迁移后配置应可载入")
	}
	if c.account.SubURL != testAcctSub || c.subscriptions[0].URL != testListSub {
		t.Fatal("迁移后数据失真")
	}
}

// TestSecretsNotSentToFrontend 下发前端的结构体里不得含任何凭证。
func TestSecretsNotSentToFrontend(t *testing.T) {
	a := seedApp()
	for name, v := range map[string]interface{}{
		"AccountInfo":      a.account,
		"SubscriptionItem": a.subscriptions[0],
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s 序列化失败: %v", name, err)
		}
		s := string(b)
		for _, secret := range []string{
			testAuthToken, testAcctSub, testListSub, "ACCTTOKEN123", "SUBTOKEN456",
		} {
			if strings.Contains(s, secret) {
				t.Fatalf("%s 下发前端的 JSON 中含凭证: %s", name, s)
			}
		}
	}
}
