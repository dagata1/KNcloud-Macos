package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// kncloudDomainQueryURL 官方域名发现接口（与安卓版一致）。
// 返回示例：{"success":true,"message":"OK","data":{"domain":"https://www.kncloud.top","type":"cloud"}}
var kncloudDomainQueryURL = "https://aws.kncloud.top/api/domain/cloud"

var domainHTTPClient = &http.Client{Timeout: 8 * time.Second}

// parseDomainResponse 从发现接口的返回中取出官网地址；只接受 https，去掉末尾斜杠。
func parseDomainResponse(body []byte) (string, bool) {
	var resp struct {
		Success *bool `json:"success"`
		Data    struct {
			Domain string `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", false
	}
	if resp.Success != nil && !*resp.Success {
		return "", false
	}
	d := strings.TrimRight(strings.TrimSpace(resp.Data.Domain), "/")
	u, err := url.Parse(d)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", false
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return "https://" + u.Host, true
}

// fetchDynamicDomain 向官方接口查询最新官网地址；失败时回退到 fallback（为空则默认域名）。
func fetchDynamicDomain(fallback string) string {
	if fallback == "" {
		fallback = kncloudDefaultDomain
	}
	req, err := http.NewRequest(http.MethodGet, kncloudDomainQueryURL, nil)
	if err != nil {
		return fallback
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "KNcloud-WIN")
	resp, err := domainHTTPClient.Do(req)
	if err != nil {
		log.Printf("[domain] 获取最新官网地址失败，使用 %s：%v", fallback, err)
		return fallback
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("[domain] 域名接口 HTTP %d，使用 %s", resp.StatusCode, fallback)
		return fallback
	}
	d, ok := parseDomainResponse(body)
	if !ok {
		log.Printf("[domain] 域名接口返回无效，使用 %s", fallback)
		return fallback
	}
	return d
}

// resolveDomain 取当前账户域名作为回退，查询最新官网地址；地址变化时写回账户并保存。
func (a *App) resolveDomain() string {
	a.mu.RLock()
	cur := a.account.Domain
	a.mu.RUnlock()
	d := fetchDynamicDomain(cur)
	if !strings.EqualFold(d, cur) {
		a.mu.Lock()
		if strings.EqualFold(a.account.Domain, cur) {
			log.Printf("[domain] 官网地址更新：%s -> %s", cur, d)
			a.account.Domain = d
			a.savePersisted()
		}
		a.mu.Unlock()
	}
	return d
}
