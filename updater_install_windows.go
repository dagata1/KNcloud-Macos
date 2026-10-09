package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func releaseZipName(tag string) string { return "KNcloud-WIN-" + tag + ".zip" }

type replacedFile struct {
	dst     string
	hadOld  bool // 原文件存在，已改名为 dst+".old"
	written bool
}

// installUpdateFiles 用 staged 目录里的文件替换程序目录中的对应文件：
//   - KNcloud.exe → exePath（保持当前 exe 的文件名）；
//   - bin/** → <root>/bin/**；
//   - 其它文件一律忽略（configs\、logs\ 绝不触碰）。
//
// 原文件先改名为 .old（运行中的 exe / 已加载的 DLL 不能覆盖但可以改名），再写入新文件。
// 任何一步失败都把已处理的文件回滚到原状。
func installUpdateFiles(staged string, files []string, root, exePath string) error {
	type pair struct{ src, dst string }
	var plan []pair
	hasExe := false
	for _, rel := range files {
		switch {
		case strings.EqualFold(rel, "KNcloud.exe"):
			plan = append(plan, pair{filepath.Join(staged, "KNcloud.exe"), exePath})
			hasExe = true
		case strings.HasPrefix(strings.ToLower(rel), "bin/"):
			dst, err := safeJoin(root, rel)
			if err != nil {
				return err
			}
			plan = append(plan, pair{filepath.Join(staged, filepath.FromSlash(rel)), dst})
		}
	}
	if !hasExe {
		return fmt.Errorf("安装包中没有 KNcloud.exe")
	}
	if err := checkPE(filepath.Join(staged, "KNcloud.exe")); err != nil {
		return err
	}

	var done []replacedFile
	rollback := func() {
		for i := len(done) - 1; i >= 0; i-- {
			r := done[i]
			if r.written {
				os.Remove(r.dst)
			}
			if r.hadOld {
				os.Rename(r.dst+".old", r.dst)
			}
		}
	}
	for _, p := range plan {
		r := replacedFile{dst: p.dst}
		if err := os.MkdirAll(filepath.Dir(p.dst), 0755); err != nil {
			rollback()
			return err
		}
		if _, err := os.Stat(p.dst); err == nil {
			os.Remove(p.dst + ".old") // 上次更新遗留
			if err := os.Rename(p.dst, p.dst+".old"); err != nil {
				rollback()
				return fmt.Errorf("无法替换 %s: %w", filepath.Base(p.dst), err)
			}
			r.hadOld = true
		}
		done = append(done, r)
		if err := copyFile(p.src, p.dst); err != nil {
			done[len(done)-1].written = true
			rollback()
			return fmt.Errorf("写入 %s 失败: %w", filepath.Base(p.dst), err)
		}
		done[len(done)-1].written = true
	}
	return nil
}

// checkPE 粗验新 exe 是 Windows 可执行文件（MZ 头），避免把损坏的文件装上去。
func checkPE(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head, []byte("MZ")) {
		return fmt.Errorf("安装包中的 KNcloud.exe 无效")
	}
	return nil
}

// cleanupAfterUpdate 启动时删除上次更新留下的 .old 文件与暂存目录。返回删除的文件数。
func cleanupAfterUpdate() int {
	root := portableRoot()
	if root == "" {
		return 0
	}
	n := 0
	if exe, err := os.Executable(); err == nil {
		if os.Remove(exe+".old") == nil {
			n++
		}
	}
	filepath.Walk(filepath.Join(root, "bin"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(p), ".old") {
			if os.Remove(p) == nil {
				n++
			}
		}
		return nil
	})
	os.RemoveAll(filepath.Join(root, "update"))
	return n
}

func (a *App) performUpdate(rel *ghRelease) error {
	tag := rel.TagName
	zipAsset := findAsset(rel, releaseZipName(tag))
	sumAsset := findAsset(rel, releaseZipName(tag)+".sha256")
	if zipAsset == nil || sumAsset == nil {
		return fmt.Errorf("发布中缺少安装包或校验文件")
	}
	root := portableRoot()
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = r
	}
	if root == "" || !strings.EqualFold(filepath.Clean(filepath.Dir(exePath)), filepath.Clean(root)) {
		return fmt.Errorf("程序目录不可写，无法在线更新，请从发布页手动下载")
	}

	staging := filepath.Join(root, "update", tag)
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0755); err != nil {
		return err
	}

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
	files, err := extractUpdateZip(zipPath, unpacked)
	if err != nil {
		return err
	}

	// 停内核 / TUN、还原系统代理，释放 bin\ 下的文件；此后无论成败都要重启程序
	a.setUpdateProgress("installing", 100, "正在停止内核并安装…")
	a.addLogInternal("info", fmt.Sprintf("Installing update %s", tag))
	a.shutdown(shutdownBudget)

	instErr := installUpdateFiles(unpacked, files, root, exePath)
	if instErr != nil {
		a.addLogInternal("error", fmt.Sprintf("Install update failed, rolled back: %v", instErr))
		a.setUpdateProgress("error", 0, "安装失败，已回滚，正在重启程序："+instErr.Error())
		time.Sleep(1500 * time.Millisecond)
	} else {
		a.setUpdateProgress("restarting", 100, "更新完成，正在重启…")
	}
	if err := relaunchSelf(exePath); err != nil {
		// 新进程起不来：恢复旧版本的内核与系统代理，保持可用
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

// relaunchSelf 启动 exePath（新版本），让它等当前进程退出后再初始化（避开单实例锁）。
func relaunchSelf(exePath string) error {
	cmd := exec.Command(exePath, "--wait-pid", strconv.Itoa(os.Getpid()))
	cmd.Dir = filepath.Dir(exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200 | 0x00000008} // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
	return cmd.Start()
}

// updateRepo 在线更新查询的 GitHub 仓库（Windows 版）。
const updateRepo = "dagata1/KNcloud-WIN"
