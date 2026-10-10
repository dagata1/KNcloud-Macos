// Package subfetch 通过本程序的本地 HTTP 代理拉取订阅内容（应用内更新也复用 NewClient）。
//
// 订阅 / 更新一律走本地 HTTP 入站（内核常开，分流 / 直连由内核按当前模式决定），不再直连兜底。
// 内核正在重启 / 重试时本地端口可能短暂不通：先等它起来（轮询端口，最多 Wait），再发请求。
// 纯标准库，可在 Linux 上跑单测；调用方在主包 app.go。
package subfetch

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// UserAgent 拉订阅时的 UA。
const UserAgent = "KNcloud-WIN/1.0"

// MaxBody 订阅内容上限。
const MaxBody = 10 << 20

// ErrProxyUnavailable 等待期满本地代理仍不可用。
var ErrProxyUnavailable = errors.New("local proxy is not available")

// Options 拉取参数。
type Options struct {
	// Port 返回本地 HTTP 代理当前端口；内核没在运行时返回 0。每次轮询都会重新调用
	// （内核重启时端口可能被自动换掉）。
	Port func() int
	// Wait 本地代理不可用时最多等待多久（例如内核正在重启 / 重试）。
	Wait time.Duration
	// Poll 等待期间的轮询间隔，默认 250ms。
	Poll time.Duration
	// Timeout 单次 HTTP 请求超时。
	Timeout time.Duration
}

// WaitPort 等本地代理端口可连，返回端口；超过 opt.Wait 返回 ErrProxyUnavailable。
func WaitPort(opt Options) (int, error) {
	poll := opt.Poll
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	deadline := time.Now().Add(opt.Wait)
	last := 0
	for {
		if p := opt.Port(); p > 0 {
			last = p
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), time.Second)
			if err == nil {
				c.Close()
				return p, nil
			}
		}
		if !time.Now().Before(deadline) {
			if last > 0 {
				return 0, fmt.Errorf("%w (127.0.0.1:%d did not accept connections within %s)", ErrProxyUnavailable, last, opt.Wait)
			}
			return 0, fmt.Errorf("%w (core not running after %s)", ErrProxyUnavailable, opt.Wait)
		}
		time.Sleep(poll)
	}
}

// NewClient 等本地代理可用（最多 opt.Wait，期间跟随端口变化），返回一个只经该代理出站的
// HTTP 客户端（Transport 显式指定代理，不读环境变量 / 系统代理，也没有直连兜底）。
// 每次请求前调用一次，内核重启换了端口时下一次请求就会用新端口。
func NewClient(opt Options) (*http.Client, error) {
	port, err := WaitPort(opt)
	if err != nil {
		return nil, err
	}
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	return &http.Client{Timeout: opt.Timeout, Transport: &http.Transport{
		Proxy:                 http.ProxyURL(pu),
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}}, nil
}

// Fetch 经本地 HTTP 代理拉取 rawURL。
func Fetch(rawURL string, opt Options) (string, error) {
	client, err := NewClient(opt)
	if err != nil {
		return "", err
	}
	return get(client, rawURL)
}

func get(client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
