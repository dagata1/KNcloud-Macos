//go:build darwin

package main

// autostart_darwin.go —— 登录自启：~/Library/LaunchAgents/top.kncloud.macos.plist（RunAtLoad）。
// 无需 launchctl load：下次登录时 launchd 自动读取该目录。

import (
	"bytes"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const launchAgentLabel = "top.kncloud.macos"

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"), nil
}

// appBundlePath 当前 exe 所在的 .app（不在 bundle 内时返回空）。
func appBundlePath() string {
	exe, err := currentExecutablePath()
	if err != nil {
		return ""
	}
	// <X>.app/Contents/MacOS/<exe>
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	bundle := filepath.Dir(contents)
	if filepath.Base(macos) == "MacOS" && filepath.Base(contents) == "Contents" && strings.HasSuffix(bundle, ".app") {
		return bundle
	}
	return ""
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func launchAgentPlist() (string, error) {
	var args []string
	if b := appBundlePath(); b != "" {
		args = []string{"/usr/bin/open", "-a", b}
	} else {
		exe, err := currentExecutablePath()
		if err != nil {
			return "", err
		}
		args = []string{exe}
	}
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchAgentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		sb.WriteString("\t\t<string>" + xmlEscape(a) + "</string>\n")
	}
	sb.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`)
	return sb.String(), nil
}

// isAutoStartEnabled LaunchAgent 是否存在。
func isAutoStartEnabled() bool {
	p, err := launchAgentPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// setAutoStart 写入 / 删除 LaunchAgent。内容相同则不重写（避免每次启动触发「已添加登录项」通知）。
func setAutoStart(enable bool) error {
	p, err := launchAgentPath()
	if err != nil {
		return err
	}
	if !enable {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	content, err := launchAgentPlist()
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(p); err == nil && string(old) == content {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0644)
}
