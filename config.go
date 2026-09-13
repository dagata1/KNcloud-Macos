package main

import (
	"encoding/json"
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
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
