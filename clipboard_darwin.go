//go:build darwin

package main

// clipboard_darwin.go —— 系统剪贴板（pbcopy / pbpaste，强制 UTF-8）。

import (
	"os"
	"os/exec"
	"strings"
)

func pbEnv() []string { return append(os.Environ(), "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8") }

func setClipboardText(text string) error {
	cmd := exec.Command("/usr/bin/pbcopy")
	cmd.Env = pbEnv()
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func clipboardText() (string, error) {
	cmd := exec.Command("/usr/bin/pbpaste")
	cmd.Env = pbEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
