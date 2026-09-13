package main

import (
	"golang.org/x/sys/windows/registry"
	"syscall"
)

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

func notifyInternetSettingsChanged() {
	internetSetOption.Call(0, uintptr(INTERNET_OPTION_SETTINGS_CHANGED), 0, 0)
	internetSetOption.Call(0, uintptr(INTERNET_OPTION_REFRESH), 0, 0)
}

func setWindowsSystemProxy(enable bool, server string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", registry.SET_VALUE)
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
	}

	notifyInternetSettingsChanged()
	return nil
}

func getWindowsSystemProxy() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", registry.QUERY_VALUE)
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
