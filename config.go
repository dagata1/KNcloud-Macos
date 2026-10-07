package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type persistedConfig struct {
	Nodes         []NodeItem         `json:"nodes"`
	Subscriptions []SubscriptionItem `json:"subscriptions"`
	Settings      AppSettings        `json:"settings"`
	RoutingMode   string             `json:"routingMode"`
	ActiveNodeID  string             `json:"activeNodeID"`
	TotalUp       int64              `json:"totalUp"`
	TotalDown     int64              `json:"totalDown"`
	Account       *AccountInfo       `json:"account"`
	// AccountToken 是加密后的登录凭证（DPAPI，见 credstore.go）。
	// AccountInfo.AuthToken 带 json:"-"（不下发给前端，见 account.go），
	// 因此不会被上面的 Account 字段一起序列化，必须在这里单独存取，
	// 否则重启后凭证丢失、用户被迫重新登录。
	AccountToken string `json:"accountToken,omitempty"`
	// AccountSubURL 是加密后的账户订阅地址。
	// 它与 AccountToken 同级敏感：拿到即可取回该账户的全部节点。
	AccountSubURL string `json:"accountSubUrl,omitempty"`
	// SubscriptionURLs 按订阅 ID 存放加密后的订阅地址。
	// SubscriptionItem.URL 带 json:"-"（不下发前端），不会随上面的
	// Subscriptions 一起序列化，必须在这里单独存取。
	SubscriptionURLs map[string]string `json:"subscriptionUrls,omitempty"`
}

func appConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		base, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(base, "AppData", "Roaming")
	}
	dir := filepath.Join(base, "KNcloud")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func configFilePath() string {
	dir, err := appConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "config.json")
}

// loadPersisted 读取用户配置；返回 false 表示首次运行（未找到有效配置）。
func (a *App) loadPersisted() bool {
	path := configFilePath()
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var cfg persistedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	if cfg.Settings.SocksPort == 0 {
		return false
	}
	a.nodes = cfg.Nodes
	if a.nodes == nil {
		a.nodes = []NodeItem{}
	}
	a.subscriptions = cfg.Subscriptions
	if a.subscriptions == nil {
		a.subscriptions = []SubscriptionItem{}
	}
	a.settings = cfg.Settings
	// 旧版本配置文件里没有 minimizeToTray 字段：默认开启「关闭窗口最小化到托盘」
	if !settingsHasKey(data, "minimizeToTray") {
		a.settings.MinimizeToTray = true
	}
	// 旧版本配置文件里没有 autoStart 字段：默认开启「开机自动启动」
	if !settingsHasKey(data, "autoStart") {
		a.settings.AutoStart = true
	}
	if cfg.RoutingMode != "" {
		a.routingMode = cfg.RoutingMode
	}
	a.activeNodeID = cfg.ActiveNodeID
	if cfg.TotalUp > 0 {
		a.totalUpBytes = cfg.TotalUp
	}
	if cfg.TotalDown > 0 {
		a.totalDownBytes = cfg.TotalDown
	}
	if cfg.Account != nil {
		a.account = *cfg.Account
		if a.account.Domain == "" {
			a.account.Domain = kncloudDefaultDomain
		}
		// 凭证走独立的加密字段（AccountInfo.AuthToken 带 json:"-"）。
		// 兼容旧配置：老版本把明文 token 写在 account.authToken 里，这里回落读取，
		// 下次保存时自动迁移为顶层 accountToken 密文。
		if cfg.AccountToken != "" {
			tok, err := decodeSecret(cfg.AccountToken)
			if err != nil {
				// 解不开就当未登录处理，避免拿着坏凭证反复请求接口
				a.addLogInternal("warn", fmt.Sprintf("Stored credential unusable (%v); please log in again", err))
				tok = ""
			}
			a.account.AuthToken = tok
		} else {
			a.account.AuthToken = legacyAccountToken(data)
		}

		// 账户订阅地址：新配置读加密字段，旧配置回落到明文 account.subUrl，
		// 下次保存时自动迁移。
		if cfg.AccountSubURL != "" {
			su, err := decodeSecret(cfg.AccountSubURL)
			if err != nil {
				a.addLogInternal("warn", fmt.Sprintf("Stored subscription address unusable (%v)", err))
				su = ""
			}
			a.account.SubURL = su
		} else {
			a.account.SubURL = legacyAccountSubURL(data)
		}
	}
	// 订阅地址：新配置从加密映射按 ID 取回；旧配置回落到明文 subscriptions[].url。
	var legacySubs map[string]string
	if len(cfg.SubscriptionURLs) == 0 {
		legacySubs = legacySubscriptionURLs(data)
	}
	for i := range a.subscriptions {
		id := a.subscriptions[i].ID
		if enc, ok := cfg.SubscriptionURLs[id]; ok {
			u, err := decodeSecret(enc)
			if err != nil {
				a.addLogInternal("warn", fmt.Sprintf("Subscription [%s] address unusable (%v); please re-add it", a.subscriptions[i].Name, err))
				u = ""
			}
			a.subscriptions[i].URL = u
		} else if u, ok := legacySubs[id]; ok {
			a.subscriptions[i].URL = u
		}
	}
	// 数据文件中可能没有 Active 标记，按 activeNodeID 恢复
	found := false
	for i := range a.nodes {
		if a.activeNodeID != "" && a.nodes[i].ID == a.activeNodeID {
			a.nodes[i].Active = true
			found = true
		} else {
			a.nodes[i].Active = false
		}
	}
	if !found && len(a.nodes) > 0 {
		a.nodes[0].Active = true
		a.activeNodeID = a.nodes[0].ID
	} else if len(a.nodes) == 0 {
		a.activeNodeID = ""
	}
	return true
}

// settingsHasKey 判断持久化 JSON 的 settings 对象里是否存在指定字段，
// 用于区分「旧配置缺少该字段」与「用户显式关闭」两种情况。
func settingsHasKey(data []byte, key string) bool {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return false
	}
	raw, ok := top["settings"]
	if !ok {
		return false
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return false
	}
	_, ok = settings[key]
	return ok
}

// savePersisted 将当前状态写入磁盘。调用方需已持有写锁（或在无并发场景调用）。
// 失败时记录日志并清理临时文件，避免残留 .tmp 影响下次写入。
func (a *App) savePersisted() {
	path := configFilePath()
	if path == "" {
		return
	}
	cfg := persistedConfig{
		Nodes:         a.nodes,
		Subscriptions: a.subscriptions,
		Settings:      a.settings,
		RoutingMode:   a.routingMode,
		ActiveNodeID:  a.activeNodeID,
		TotalUp:       a.totalUpBytes,
		TotalDown:     a.totalDownBytes,
		Account:       &a.account,
	}
	// 凭证加密后落盘。加密失败时宁可不写：安全功能必须 fail-closed，
	// 退回明文等于这道防护从未存在。代价只是下次启动需重新登录。
	if tok, err := encodeSecret(a.account.AuthToken); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Credential not persisted (%v); you may need to log in again next time", err))
	} else {
		cfg.AccountToken = tok
	}
	if su, err := encodeSecret(a.account.SubURL); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Subscription address not persisted (%v)", err))
	} else {
		cfg.AccountSubURL = su
	}
	// 订阅地址逐条加密。单条失败只丢这一条，不影响其余订阅。
	if len(a.subscriptions) > 0 {
		urls := make(map[string]string, len(a.subscriptions))
		for _, sub := range a.subscriptions {
			if sub.URL == "" {
				continue
			}
			enc, err := encodeSecret(sub.URL)
			if err != nil {
				a.addLogInternal("error", fmt.Sprintf("Subscription [%s] address not persisted (%v)", sub.Name, err))
				continue
			}
			urls[sub.ID] = enc
		}
		if len(urls) > 0 {
			cfg.SubscriptionURLs = urls
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		a.addLogInternal("error", fmt.Sprintf("Failed to marshal config: %v", err))
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Failed to write config tmp file: %v", err))
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		// 清理残留的临时文件，避免下次写入时混淆
		_ = os.Remove(tmp)
		a.addLogInternal("error", fmt.Sprintf("Failed to save config: %v", err))
		return
	}
}

// legacyAccountToken 从旧版配置里读取 account.authToken（明文）。
// 旧版本 AccountInfo.AuthToken 参与 JSON 序列化，凭证就存在 account 对象内；
// 现在该字段改为 json:"-" 并单独加密，读取时需要这个兼容路径，否则老用户升级后要重新登录。
func legacyAccountToken(data []byte) string {
	var top struct {
		Account struct {
			AuthToken string `json:"authToken"`
		} `json:"account"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return ""
	}
	return top.Account.AuthToken
}

// legacyAccountSubURL 从旧版配置里读取 account.subUrl（明文）。
func legacyAccountSubURL(data []byte) string {
	var top struct {
		Account struct {
			SubURL string `json:"subUrl"`
		} `json:"account"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return ""
	}
	return top.Account.SubURL
}

// legacySubscriptionURLs 从旧版配置里读取 subscriptions[].url（明文），
// 返回 ID -> URL 映射。用于升级迁移，下次保存即写入加密字段。
func legacySubscriptionURLs(data []byte) map[string]string {
	var top struct {
		Subscriptions []struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"subscriptions"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return nil
	}
	out := make(map[string]string, len(top.Subscriptions))
	for _, s := range top.Subscriptions {
		if s.ID != "" && s.URL != "" {
			out[s.ID] = s.URL
		}
	}
	return out
}
