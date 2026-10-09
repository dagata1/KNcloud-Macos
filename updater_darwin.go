//go:build darwin

package main

// updater_darwin.go —— macOS 在线更新：
//
//	下载 KNcloud-macOS-<tag>.zip 与 .sha256（KNcloud-Macos 仓库的 Release）→ 校验 SHA256
//	→ ditto 解压到 ~/Library/Application Support/KNcloud/update/<tag>
//	→ 校验新 .app 的可执行文件是 Mach-O → 停内核 / TUN、还原系统代理
//	→ 当前 .app 改名为 .app.old，新 .app 移入原位置（失败回滚）
//	→ open -n 启动新版本（--wait-pid 等旧进程退出）→ 旧进程退出；新进程启动时删除 .old。
//
// 不在 .app 内运行（开发构建）或 .app 所在目录不可写时，提示用户从发布页手动下载。

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func updateStagingRoot() string {
	dir, err := appConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "update")
}

// cleanupAfterUpdate 启动时删除上次更新留下的 .app.old 与暂存目录。返回删除的项数。
func cleanupAfterUpdate() int {
	n := 0
	if b := appBundlePath(); b != "" {
		if _, err := os.Stat(b + ".old"); err == nil {
			if os.RemoveAll(b+".old") == nil {
				n++
			}
		}
	}
	if s := updateStagingRoot(); s != "" {
		os.RemoveAll(s)
	}
	return n
}

// checkMachO 粗验可执行文件是 Mach-O（含 universal fat 二进制）。
func checkMachO(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return fmt.Errorf("安装包中的程序无效")
	}
	for _, magic := range [][]byte{{0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}, {0xce, 0xfa, 0xed, 0xfe}} {
		if bytes.Equal(head, magic) {
			return nil
		}
	}
	return fmt.Errorf("安装包中的程序不是 macOS 可执行文件")
}

// findStagedApp 在解压目录里找 .app，并校验其主程序。
func findStagedApp(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".app") {
			continue
		}
		app := filepath.Join(dir, e.Name())
		bins, err := os.ReadDir(filepath.Join(app, "Contents", "MacOS"))
		if err != nil || len(bins) == 0 {
			continue
		}
		for _, b := range bins {
			if err := checkMachO(filepath.Join(app, "Contents", "MacOS", b.Name())); err == nil {
				return app, nil
			}
		}
	}
	return "", fmt.Errorf("安装包中没有有效的 KNcloud.app")
}

func (a *App) performUpdate(rel *ghRelease) error {
	tag := rel.TagName
	zipAsset := findAsset(rel, releaseZipName(tag))
	sumAsset := findAsset(rel, releaseZipName(tag)+".sha256")
	if zipAsset == nil || sumAsset == nil {
		return fmt.Errorf("发布中缺少安装包或校验文件")
	}
	bundle := appBundlePath()
	if bundle == "" {
		return fmt.Errorf("当前不是从 KNcloud.app 运行，无法在线更新，请从发布页手动下载")
	}
	probe := filepath.Join(filepath.Dir(bundle), ".kncloud-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0644); err != nil {
		return fmt.Errorf("程序所在目录不可写，无法在线更新，请从发布页手动下载")
	}
	os.Remove(probe)

	root := updateStagingRoot()
	if root == "" {
		return fmt.Errorf("无法确定更新暂存目录")
	}
	staging := filepath.Join(root, tag)
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0755); err != nil {
		return err
	}
	defer func() {
		// 成功时新进程启动会再清一次；失败时这里清理
		go func() { time.Sleep(3 * time.Second); os.RemoveAll(staging) }()
	}()

	a.setUpdateProgress("downloading", 0, "正在下载校验文件…")
	sumData, err := a.fetchSmall(sumAsset.URL)
	if err != nil {
		return fmt.Errorf("下载校验文件失败: %w", err)
	}
	wantSum, err := parseSHA256File(sumData, zipAsset.Name)
	if err != nil {
		return err
	}

	a.setUpdateProgress("downloading", 0, "正在下载 "+tag+"…")
	zipPath := filepath.Join(staging, zipAsset.Name)
	gotSum, err := a.downloadTo(zipAsset.URL, zipPath, zipAsset.Size, func(p int) {
		a.setUpdateProgress("downloading", p, fmt.Sprintf("正在下载 %s… %d%%", tag, p))
	})
	if err != nil {
		return fmt.Errorf("下载安装包失败: %w", err)
	}
	a.setUpdateProgress("verifying", 100, "正在校验安装包…")
	if !strings.EqualFold(gotSum, wantSum) {
		os.Remove(zipPath)
		return fmt.Errorf("安装包校验失败（SHA256 不匹配），已放弃更新")
	}

	a.setUpdateProgress("extracting", 100, "正在解压…")
	unpacked := filepath.Join(staging, "files")
	// ditto 保留 .app 内的符号链接、可执行位与签名
	if out, err := exec.Command("/usr/bin/ditto", "-x", "-k", zipPath, unpacked).CombinedOutput(); err != nil {
		return fmt.Errorf("解压失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	newApp, err := findStagedApp(unpacked)
	if err != nil {
		return err
	}
	_ = exec.Command("/usr/bin/xattr", "-dr", "com.apple.quarantine", newApp).Run()

	a.setUpdateProgress("installing", 100, "正在停止内核并安装…")
	a.addLogInternal("info", fmt.Sprintf("Installing update %s", tag))
	a.shutdown(shutdownBudget)

	instErr := replaceAppBundle(bundle, newApp)
	if instErr != nil {
		a.addLogInternal("error", fmt.Sprintf("Install update failed, rolled back: %v", instErr))
		a.setUpdateProgress("error", 0, "安装失败，已回滚，正在重启程序："+instErr.Error())
		time.Sleep(1500 * time.Millisecond)
	} else {
		a.setUpdateProgress("restarting", 100, "更新完成，正在重启…")
	}
	if err := relaunchSelf(bundle); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Relaunch failed: %v", err))
		a.cleaned.Store(false)
		go a.RestartCore()
		if instErr != nil {
			return instErr
		}
		return fmt.Errorf("已安装新版本，但自动重启失败，请手动重新打开程序: %w", err)
	}
	go a.quitApp()
	return instErr
}

// replaceAppBundle 当前 .app → .app.old，新 .app 移入原位置；任何一步失败回滚。
func replaceAppBundle(bundle, newApp string) error {
	old := bundle + ".old"
	os.RemoveAll(old)
	if err := os.Rename(bundle, old); err != nil {
		return fmt.Errorf("无法替换 %s: %w", filepath.Base(bundle), err)
	}
	if err := os.Rename(newApp, bundle); err != nil {
		// 跨卷时 rename 失败：用 ditto 复制
		if out, derr := exec.Command("/usr/bin/ditto", newApp, bundle).CombinedOutput(); derr != nil {
			os.RemoveAll(bundle)
			os.Rename(old, bundle)
			return fmt.Errorf("写入新版本失败: %v: %s", derr, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// relaunchSelf 用 open -n 启动（新版本的）.app，让它等当前进程退出后再初始化（避开单实例锁）。
func relaunchSelf(bundle string) error {
	return exec.Command("/usr/bin/open", "-n", bundle, "--args", "--wait-pid", strconv.Itoa(os.Getpid())).Start()
}
