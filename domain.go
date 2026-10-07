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

// domainCheckInterval 查询官网地址的最短间隔：每周一次。
const domainCheckInterval = 7 * 24 * time.Hour

// domainCheckDue 是否到了每周查询官网地址的时间（纯函数，便于测试）。
func domainCheckDue(now time.Time, last int64) bool {
	return last <= 0 || now.Sub(time.Unix(last, 0)) >= domainCheckInterval
}

// weeklyResolveDomain 只在自动更新订阅时调用：距上次查询满一周才请求域名接口，
// 其余时间一律使用已保存的官网地址（默认 www.kncloud.top）。
// 无论查询成功与否都记录时间，失败也要等下周，避免频繁请求。
func (a *App) weeklyResolveDomain(now time.Time) {
	a.mu.RLock()
	cur := a.account.Domain
	last := a.account.DomainCheckedAt
	a.mu.RUnlock()
	if !domainCheckDue(now, last) {
		return
	}
	d := fetchDynamicDomain(cur)
	a.mu.Lock()
	a.account.DomainCheckedAt = now.Unix()
	if !strings.EqualFold(d, a.account.Domain) {
		log.Printf("[domain] 官网地址更新：%s -> %s", a.account.Domain, d)
		a.account.Domain = d
	}
	a.savePersisted()
	a.mu.Unlock()
}
