package main

import (
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

const internetSettingsKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

// ourProxyServer 本进程最近一次写入并启用的系统代理地址（如 127.0.0.1:10809）；空表示未启用。
// 退出时拿不到 a.mu 也能据此判断注册表里的代理是不是我们设的，只还原自己的。
var ourProxyServer atomic.Value // string

// notifyInternetSettingsChanged 通知 WinINet 重新读取代理设置。
//
// InternetSetOption 是同步调用，个别环境（WPAD 自动探测、WinINet 内部锁争用）下会卡住数秒乃至更久；
// 注册表已经写好，通知只是让已打开的应用尽快生效，所以最多等 2 秒，剩下的交给后台完成。
func notifyInternetSettingsChanged() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		internetSetOption.Call(0, uintptr(INTERNET_OPTION_SETTINGS_CHANGED), 0, 0)
		internetSetOption.Call(0, uintptr(INTERNET_OPTION_REFRESH), 0, 0)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func setSystemProxy(enable bool, server string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	val := uint32(0)
	if enable {
		val = 1
	}
	if err := k.SetDWordValue("ProxyEnable", val); err != nil {
		return err
	}

	if enable && server != "" {
		if err := k.SetStringValue("ProxyServer", server); err != nil {
			return err
		}
		ourProxyServer.Store(server)
	}
	if !enable {
		ourProxyServer.Store("")
	}

	notifyInternetSettingsChanged()
	return nil
}

// restoreSystemProxyIfOurs 不依赖 App 状态的兜底还原：注册表里启用的系统代理
// 正是本进程设置的那个地址时才关闭它，不碰用户或其它软件的代理设置。
func restoreSystemProxyIfOurs() {
	ours, _ := ourProxyServer.Load().(string)
	if ours == "" {
		return
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	enabled, _, err1 := k.GetIntegerValue("ProxyEnable")
	server, _, err2 := k.GetStringValue("ProxyServer")
	k.Close()
	if err1 != nil || err2 != nil || enabled != 1 || !strings.EqualFold(strings.TrimSpace(server), ours) {
		return
	}
	setSystemProxy(false, "")
}

func getSystemProxy() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		return false
	}
	return val == 1
}
