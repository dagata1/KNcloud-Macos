package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const kncloudDefaultDomain = "https://www.KNcloud.top"

// AccountInfo KNcloud 官网账户信息（V2Board 面板）
type AccountInfo struct {
	LoggedIn       bool   `json:"loggedIn"`
	Skipped        bool   `json:"skipped"`
	Email          string `json:"email"`
	Domain         string `json:"domain"`
	PlanName       string `json:"planName"`
	TransferEnable int64  `json:"transferEnable"` // 总流量（字节）
	UsedUp         int64  `json:"usedUp"`         // 已用上行（字节）
	UsedDown       int64  `json:"usedDown"`       // 已用下行（字节）
	Expire         string `json:"expire"`         // 格式化到期时间
	AuthToken      string `json:"authToken"`      // V2Board 登录凭证（用于刷新用量）
	SubURL         string `json:"subUrl"`
	SubID          string `json:"subId"` // 关联的订阅 ID
}

func defaultAccount() AccountInfo {
	return AccountInfo{Domain: kncloudDefaultDomain}
}

func (a *App) GetAccount() AccountInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.account
}

// SkipLogin 跳过登录（下次不再自动弹出，可在订阅管理页重新登录）
func (a *App) SkipLogin() AccountInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.account.Skipped = true
	a.savePersisted()
	return a.account
}

// Logout 退出登录：清除凭证，保留已导入的节点与订阅
func (a *App) Logout() AccountInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.account = AccountInfo{Domain: firstNonEmpty(a.account.Domain, kncloudDefaultDomain)}
	a.savePersisted()
	return a.account
}

// Login 登录 KNcloud 官网账户：换取 token → 拉取订阅地址与套餐 → 自动导入订阅节点
func (a *App) Login(email, password string) (AccountInfo, error) {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return a.GetAccount(), fmt.Errorf("please enter email and password")
	}

	a.mu.RLock()
	domain := a.account.Domain
	a.mu.RUnlock()
	if domain == "" {
		domain = kncloudDefaultDomain
	}

	token, err := v2boardLogin(domain, email, password)
	if err != nil {
		return a.GetAccount(), err
	}
	return a.completeLogin(domain, email, token)
}

// completeLogin 用已有凭证（auth_data）完成登录：拉取订阅地址与套餐 → 写入账户 → 导入订阅节点。
// 密码登录与网页授权回传（weblogin.go）共用此入口。
func (a *App) completeLogin(domain, email, token string) (AccountInfo, error) {
	transfer, usedUp, usedDown, expire, planName, subURL, err := v2boardGetSubscribe(domain, token)
	if err != nil {
		return a.GetAccount(), fmt.Errorf("login succeeded, but failed to fetch subscription: %v", err)
	}
	if subURL == "" {
		return a.GetAccount(), fmt.Errorf("login succeeded, but no valid subscription URL found")
	}

	// 写入账户并关联订阅
	var subID string
	a.mu.Lock()
	a.account = AccountInfo{
		LoggedIn:       true,
		Skipped:        false,
		Email:          email,
		Domain:         domain,
		PlanName:       planName,
		TransferEnable: transfer,
		UsedUp:         usedUp,
		UsedDown:       usedDown,
		Expire:         expire,
		AuthToken:      token,
		SubURL:         subURL,
	}
	// 已有相同 URL 的订阅则复用，否则新建
	for i := range a.subscriptions {
		if a.subscriptions[i].URL == subURL {
			subID = a.subscriptions[i].ID
			break
		}
	}
	if subID == "" {
		subID = fmt.Sprintf("sub-%d", time.Now().UnixNano())
		a.subscriptions = append(a.subscriptions, SubscriptionItem{
			ID:        subID,
			Name:      "KNcloud 账户订阅",
			URL:       subURL,
			UpdatedAt: time.Now().Format("2006-01-02 15:04"),
		})
	}
	a.account.SubID = subID
	a.savePersisted()
	a.mu.Unlock()

	// 拉取订阅节点（refreshSubscription 内部自行加锁）
	if err := a.refreshSubscription(subID); err != nil {
		a.mu.RLock()
		cur := a.account
		a.mu.RUnlock()
		return cur, nil // 节点拉取失败不算登录失败，可稍后手动更新
	}
	return a.GetAccount(), nil
}

// RefreshAccount 用登录凭证重新拉取套餐流量/到期信息；订阅地址变化时同步更新
func (a *App) RefreshAccount() (AccountInfo, error) {
	a.mu.RLock()
	loggedIn := a.account.LoggedIn
	domain := a.account.Domain
	token := a.account.AuthToken
	oldSubURL := a.account.SubURL
	subID := a.account.SubID
	a.mu.RUnlock()

	if !loggedIn || token == "" {
		return a.GetAccount(), fmt.Errorf("not logged in")
	}

	transfer, usedUp, usedDown, expire, planName, subURL, err := v2boardGetSubscribe(domain, token)
	if err != nil {
		if err == errTokenInvalid {
			a.mu.Lock()
			a.account = AccountInfo{Domain: domain}
			a.savePersisted()
			a.mu.Unlock()
		}
		return a.GetAccount(), err
	}

	a.mu.Lock()
	a.account.PlanName = planName
	a.account.TransferEnable = transfer
	a.account.UsedUp = usedUp
	a.account.UsedDown = usedDown
	a.account.Expire = expire
	urlChanged := subURL != "" && subURL != oldSubURL
	if urlChanged {
		a.account.SubURL = subURL
		for i := range a.subscriptions {
			if a.subscriptions[i].ID == subID {
				a.subscriptions[i].URL = subURL
				break
			}
		}
	}
	a.savePersisted()
	a.mu.Unlock()

	// 订阅地址变了才重新拉节点；平时刷新用量不动节点
	if urlChanged && subID != "" {
		_ = a.refreshSubscription(subID)
	}
	return a.GetAccount(), nil
}

// ------------------------- V2Board API -------------------------

// fetchV2boardEmail 用登录凭证拉取账户邮箱（网页授权回传只带 token 时补全用），失败返回空串
func fetchV2boardEmail(domain, token string) string {
	domain = strings.TrimRight(domain, "/")
	req, err := http.NewRequest("GET", domain+"/api/v1/user/info", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	var out struct {
		Data struct {
			Email string `json:"email"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &out) != nil {
		return ""
	}
	return out.Data.Email
}

func v2boardLogin(domain, email, password string) (string, error) {
	domain = strings.TrimRight(domain, "/")
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, err := http.NewRequest("POST", domain+"/api/v1/passport/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to connect to %s: %v", domain, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}

	var out struct {
		Data   map[string]interface{} `json:"data"`
		Message string               `json:"message"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("failed to parse response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 || out.Data == nil {
		msg := out.Message
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("login failed: %s", msg)
	}
	token := ""
	if v, ok := out.Data["auth_data"].(string); ok {
		token = v
	} else if v, ok := out.Data["token"].(string); ok {
		token = v
	}
	if token == "" {
		return "", fmt.Errorf("no token in login response")
	}
	return token, nil
}

// v2boardGetSubscribe 返回 (总流量, 已用上行, 已用下行, 到期描述, 套餐名, 订阅地址, err)
var errTokenInvalid = fmt.Errorf("session expired, please log in again")

func v2boardGetSubscribe(domain, token string) (int64, int64, int64, string, string, string, error) {
	domain = strings.TrimRight(domain, "/")
	req, err := http.NewRequest("GET", domain+"/api/v1/user/getSubscribe", nil)
	if err != nil {
		return 0, 0, 0, "", "", "", err
	}
	req.Header.Set("Authorization", token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, 0, "", "", "", fmt.Errorf("unable to connect to %s: %v", domain, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return 0, 0, 0, "", "", "", errTokenInvalid
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, 0, 0, "", "", "", err
	}

	var out struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Data == nil {
		return 0, 0, 0, "", "", "", fmt.Errorf("failed to parse subscription data (HTTP %d)", resp.StatusCode)
	}
	d := out.Data

	getInt := func(key string) int64 {
		switch v := d[key].(type) {
		case float64:
			return int64(v)
		case string:
			var n int64
			fmt.Sscanf(v, "%d", &n)
			return n
		}
		return 0
	}
	getStr := func(key string) string {
		v, _ := d[key].(string)
		return v
	}

	subURL := getStr("subscribe_url")
	if subURL == "" {
		if t := getStr("token"); t != "" {
			subURL = domain + "/api/v1/client/subscribe?token=" + t
		}
	}

	planName := ""
	if plan, ok := d["plan"].(map[string]interface{}); ok {
		planName, _ = plan["name"].(string)
	}

	expireStr := "长期有效"
	if exp := getInt("expire"); exp > 0 {
		expireStr = time.Unix(exp, 0).Format("2006-01-02 到期")
	}

	return getInt("transfer_enable"), getInt("u"), getInt("d"), expireStr, planName, subURL, nil
}

// SyncNodes 手动同步 KNcloud 账户订阅节点
func (a *App) SyncNodes() error {
	a.mu.RLock()
	loggedIn := a.account.LoggedIn
	subID := a.account.SubID
	a.mu.RUnlock()
	if !loggedIn || subID == "" {
		return fmt.Errorf("not logged into KNcloud account")
	}
	return a.refreshSubscription(subID)
}
