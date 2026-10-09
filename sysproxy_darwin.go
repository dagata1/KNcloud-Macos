//go:build darwin

package main

// sysproxy_darwin.go —— macOS 系统代理：对所有启用中的网络服务执行
// networksetup -setwebproxy / -setsecurewebproxy / -setsocksfirewallproxy，
// 关闭时只把三个开关置为 off（与 Windows 只改 ProxyEnable 一致）。
//
// 管理员账户下 networksetup 改代理不需要密码；标准（非管理员）账户会失败并记入日志。

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ourProxyServer 本进程最近一次写入并启用的 HTTP 代理（127.0.0.1:port），空表示未启用。
var ourProxyServer atomic.Value // string

// sysProxySocksPort SOCKS 入站端口（main_darwin 启动时由设置写入；0 表示不设 SOCKS 代理）。
var sysProxySocksPort atomic.Int32

const networksetupBin = "/usr/sbin/networksetup"

func networksetup(args ...string) (string, error) {
	cmd := exec.Command(networksetupBin, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return string(out), fmt.Errorf("networksetup %s timed out", strings.Join(args, " "))
	}
	s := strings.TrimSpace(string(out))
	if err == nil && strings.Contains(s, "** Error") {
		err = fmt.Errorf("%s", s)
	}
	return s, err
}

// proxyServices 需要设置代理的网络服务（全部启用中的服务，含当前未连接的，换网后依然生效）。
func proxyServices() ([]string, error) { return networkServices() }

// forEachService 并发地对每个服务执行 fn，返回第一个错误与成功个数。
func forEachService(svcs []string, fn func(svc string) error) (int, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	ok := 0
	for _, s := range svcs {
		wg.Add(1)
		go func(svc string) {
			defer wg.Done()
			err := fn(svc)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %v", svc, err)
				}
				return
			}
			ok++
		}(s)
	}
	wg.Wait()
	return ok, firstErr
}

func setSystemProxy(enable bool, server string) error {
	svcs, err := proxyServices()
	if err != nil {
		return fmt.Errorf("list network services: %v", err)
	}
	if len(svcs) == 0 {
		return fmt.Errorf("no enabled network service")
	}
	if !enable {
		_, ferr := forEachService(svcs, func(svc string) error {
			var errs []string
			for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
				if out, err := networksetup(flag, svc, "off"); err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v %s", flag, err, out))
				}
			}
			if len(errs) > 0 {
				return fmt.Errorf("%s", strings.Join(errs, "; "))
			}
			return nil
		})
		ourProxyServer.Store("")
		return ferr
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("bad proxy address %q: %v", server, err)
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return fmt.Errorf("bad proxy port %q", portStr)
	}
	socks := int(sysProxySocksPort.Load())
	ok, ferr := forEachService(svcs, func(svc string) error {
		if out, err := networksetup("-setwebproxy", svc, host, portStr); err != nil {
			return fmt.Errorf("%v %s", err, out)
		}
		if out, err := networksetup("-setsecurewebproxy", svc, host, portStr); err != nil {
			return fmt.Errorf("%v %s", err, out)
		}
		if socks > 0 {
			if out, err := networksetup("-setsocksfirewallproxy", svc, host, strconv.Itoa(socks)); err != nil {
				return fmt.Errorf("%v %s", err, out)
			}
		}
		return nil
	})
	if ok == 0 && ferr != nil {
		return ferr
	}
	ourProxyServer.Store(server)
	return nil
}

// webProxyOf 读取某服务的 HTTP 代理（是否启用与地址）。
func webProxyOf(svc string) (enabled bool, server string) {
	out, err := networksetup("-getwebproxy", svc)
	if err != nil {
		return false, ""
	}
	var host, port string
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			enabled = strings.EqualFold(v, "Yes")
		case "Server":
			host = v
		case "Port":
			port = v
		}
	}
	if host != "" && port != "" {
		server = net.JoinHostPort(host, port)
	}
	return enabled, server
}

// restoreSystemProxyIfOurs 只在系统代理仍指向本进程设置的地址时关闭它。
func restoreSystemProxyIfOurs() {
	ours, _ := ourProxyServer.Load().(string)
	if ours == "" {
		return
	}
	svcs, err := proxyServices()
	if err != nil {
		return
	}
	for _, svc := range svcs {
		if on, srv := webProxyOf(svc); on && strings.EqualFold(srv, ours) {
			_ = setSystemProxy(false, "")
			return
		}
	}
}

// getSystemProxy 任一启用中的网络服务开着 HTTP 代理即视为系统代理已开。
func getSystemProxy() bool {
	svcs, err := proxyServices()
	if err != nil {
		return false
	}
	for _, svc := range svcs {
		if on, _ := webProxyOf(svc); on {
			return true
		}
	}
	return false
}
