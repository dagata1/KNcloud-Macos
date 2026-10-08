package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const deepLinkKeyPath = `Software\Classes\` + deepLinkScheme

// registerURLProtocol 在 HKCU 注册 kncloud:// 协议，指向当前 exe（无需管理员）。
// 每次启动都会校正，程序换了安装位置也能跟着更新。
func registerURLProtocol() error {
	exe, err := currentExecutablePath()
	if err != nil {
		return err
	}
	command := fmt.Sprintf(`"%s" "%%1"`, exe)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, deepLinkKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("", "URL:KNcloud Protocol"); err != nil {
		return err
	}
	if err := k.SetStringValue("URL Protocol", ""); err != nil {
		return err
	}

	icon, _, err := registry.CreateKey(registry.CURRENT_USER, deepLinkKeyPath+`\DefaultIcon`, registry.SET_VALUE)
	if err == nil {
		_ = icon.SetStringValue("", fmt.Sprintf(`"%s",0`, exe))
		icon.Close()
	}

	cmd, _, err := registry.CreateKey(registry.CURRENT_USER, deepLinkKeyPath+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer cmd.Close()
	return cmd.SetStringValue("", command)
}
