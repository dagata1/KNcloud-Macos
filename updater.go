package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ------------------------- 手动在线更新（GitHub Releases） -------------------------
//
// 纯手动：不自动检查、不弹窗、不后台安装。用户在「首选项设置」点「检查更新」，
// 有新版本时显示版本号与更新说明，用户再点「立即更新」才会下载安装：
//
//	下载 KNcloud-WIN-<tag>.zip 与 KNcloud-WIN-<tag>.zip.sha256 → 校验 SHA256
//	→ 解压到 <程序目录>\update\<tag>（防 zip-slip）→ 停内核 / TUN、还原系统代理
//	→ 运行中的 exe 改名为 .old 后写入新 exe，bin\ 下的文件同样处理（configs\、logs\ 不碰）
//	→ 启动新 exe（--wait-pid 等旧进程退出，避开单实例锁）→ 旧进程退出；
//	新进程启动时删除 .old 与 update\ 暂存目录。
//
// 任何一步失败：已替换的文件全部回滚；内核已停的话重新启动旧程序。

// appVersion 由 CI 通过 -ldflags "-X main.appVersion=<tag>" 注入；本地构建为 dev。
var appVersion = "dev"

// updateLatestAPI 最新发布查询地址（变量仅供测试替换）。
var updateLatestAPI = "https://api.github.com/repos/" + updateRepo + "/releases/latest"

const (
	updateRepo        = "dagata1/KNcloud-WIN"
	updateEvent       = "kncloud:update-progress"
	updateMaxZipBytes = 200 << 20 // 发布包上限（防异常大文件）
	updateMaxUnpacked = 400 << 20 // 解压总量上限（防 zip 炸弹）
)

// UpdateInfo 检查更新的结果（下发前端）。
type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
	IsDev          bool   `json:"isDev"`
	Notes          string `json:"notes"`
	PublishedAt    string `json:"publishedAt"`
	ReleaseURL     string `json:"releaseUrl"`
	AssetSize      int64  `json:"assetSize"`
	Message        string `json:"message"`
}

// UpdateProgress 更新进度（kncloud:update-progress 事件与 GetUpdateProgress 返回）。
// Stage: idle / downloading / verifying / extracting / installing / restarting / error
type UpdateProgress struct {
	Stage   string `json:"stage"`
	Percent int    `json:"percent"`
	Message string `json:"message"`
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt string    `json:"published_at"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	Assets      []ghAsset `json:"assets"`
}

// updater 更新状态，独立于 a.mu（检查/下载耗时很长，绝不能占用核心状态锁）。
type updater struct {
	mu       sync.Mutex
	latest   *ghRelease // 最近一次检查到的、比当前版本新的发布
	running  bool
	progress UpdateProgress
}

var upd = &updater{progress: UpdateProgress{Stage: "idle"}}

// ------------------------- 版本比较 -------------------------

var semverRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// parseVersion 解析 v1.3.26 / 1.3 / v2.0.0-beta.1；不是版本号（如 dev、提交哈希）返回 ok=false。
func parseVersion(s string) (nums [3]int, pre string, ok bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nums, "", false
	}
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return nums, "", false
			}
			nums[i] = n
		}
	}
	return nums, m[4], true
}

// compareVersions 比较两个版本号：a<b 返回 -1，相等 0，a>b 1。
// 数字部分相同时正式版大于预发布版；预发布标识按 semver 规则逐段比较。
// 任一方无法解析时返回 0（视为无法比较，调用方据此不提示更新）。
func compareVersions(a, b string) int {
	na, pa, oka := parseVersion(a)
	nb, pb, okb := parseVersion(b)
	if !oka || !okb {
		return 0
	}
	for i := 0; i < 3; i++ {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	sa, sb := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(sa) && i < len(sb); i++ {
		if sa[i] == sb[i] {
			continue
		}
		ia, ea := strconv.Atoi(sa[i])
		ib, eb := strconv.Atoi(sb[i])
		switch {
		case ea == nil && eb == nil:
			if ia < ib {
				return -1
			}
			return 1
		case ea == nil:
			return -1 // 数字标识小于字母标识
		case eb == nil:
			return 1
		case sa[i] < sb[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(sa) < len(sb):
		return -1
	case len(sa) > len(sb):
		return 1
	}
	return 0
}

func isDevVersion(v string) bool {
	_, _, ok := parseVersion(v)
	return !ok
}

// ------------------------- HTTP -------------------------

// updateClients 按顺序返回要尝试的 HTTP 客户端：内核在跑且不是「全局直连」时先走本程序自己的
// HTTP 代理（国内直连 GitHub 常常很慢），失败再直连；否则只直连。
func (a *App) updateClients(timeout time.Duration) []*http.Client {
	direct := &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}}
	var out []*http.Client
	if a.mu.TryRLock() {
		running := a.coreRunning
		port := a.settings.HttpPort
		mode := a.routingMode
		a.mu.RUnlock()
		if running && port > 0 && mode != "direct" {
			pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			out = append(out, &http.Client{Timeout: timeout, Transport: &http.Transport{
				Proxy:                 http.ProxyURL(pu),
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			}})
		}
	}
	return append(out, direct)
}

func updateRequest(ctx context.Context, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "KNcloud-WIN/"+appVersion)
	return req, nil
}

// fetchLatestRelease 拉取最新正式发布信息。
func (a *App) fetchLatestRelease() (*ghRelease, error) {
	var lastErr error
	for _, c := range a.updateClients(20 * time.Second) {
		req, err := updateRequest(context.Background(), updateLatestAPI)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("GitHub 返回 HTTP %d", resp.StatusCode)
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("GitHub 返回 404：发布仓库不可公开访问或尚无正式发布")
			}
			continue
		}
		var rel ghRelease
		if err := json.Unmarshal(data, &rel); err != nil {
			return nil, fmt.Errorf("解析发布信息失败: %w", err)
		}
		return &rel, nil
	}
	return nil, fmt.Errorf("无法连接 GitHub：%v", lastErr)
}

func releaseZipName(tag string) string { return "KNcloud-WIN-" + tag + ".zip" }

func findAsset(rel *ghRelease, name string) *ghAsset {
	for i := range rel.Assets {
		if strings.EqualFold(rel.Assets[i].Name, name) {
			return &rel.Assets[i]
		}
	}
	return nil
}

// ------------------------- 绑定：版本 / 检查 / 更新 -------------------------

// GetAppVersion 当前程序版本（CI 注入的 tag；本地构建为 dev）。
func (a *App) GetAppVersion() string { return appVersion }

// CheckForUpdate 「检查更新」按钮：查询 GitHub 最新发布并与当前版本比较。不会自动下载。
func (a *App) CheckForUpdate() (UpdateInfo, error) {
	info := UpdateInfo{CurrentVersion: appVersion, IsDev: isDevVersion(appVersion)}
	rel, err := a.fetchLatestRelease()
	if err != nil {
		a.addLogInternal("warn", fmt.Sprintf("Update check failed: %v", err))
		return info, err
	}
	info.LatestVersion = rel.TagName
	info.Notes = summarizeNotes(rel.Body, 1500)
	info.PublishedAt = rel.PublishedAt
	info.ReleaseURL = rel.HTMLURL
	if z := findAsset(rel, releaseZipName(rel.TagName)); z != nil {
		info.AssetSize = z.Size
	}

	upd.mu.Lock()
	upd.latest = nil
	upd.mu.Unlock()

	switch {
	case info.IsDev:
		info.Message = "当前是开发版本（dev），不支持在线更新，请从发布页手动下载"
	case compareVersions(rel.TagName, appVersion) <= 0:
		info.Message = "已是最新版本"
	case findAsset(rel, releaseZipName(rel.TagName)) == nil:
		info.Message = "发现新版本，但发布中缺少安装包，请稍后再试或前往发布页下载"
	case findAsset(rel, releaseZipName(rel.TagName)+".sha256") == nil:
		info.Message = "发现新版本，但发布中缺少校验文件（.sha256），为安全起见不在线安装，请前往发布页下载"
	default:
		info.HasUpdate = true
		info.Message = "发现新版本"
		upd.mu.Lock()
		upd.latest = rel
		upd.mu.Unlock()
	}
	a.addLogInternal("info", fmt.Sprintf("Update check: current %s, latest %s, update=%v", appVersion, rel.TagName, info.HasUpdate))
	return info, nil
}

// GetUpdateProgress 前端（重新）打开设置页时查询更新进度。
func (a *App) GetUpdateProgress() UpdateProgress {
	upd.mu.Lock()
	defer upd.mu.Unlock()
	return upd.progress
}

// StartUpdate 「立即更新」按钮：后台下载并安装上一次检查到的新版本，立即返回；
// 进度通过 kncloud:update-progress 推送。完成后程序自动重启。
func (a *App) StartUpdate() error {
	upd.mu.Lock()
	if upd.running {
		upd.mu.Unlock()
		return fmt.Errorf("更新正在进行中")
	}
	rel := upd.latest
	if rel == nil {
		upd.mu.Unlock()
		return fmt.Errorf("请先检查更新")
	}
	if isDevVersion(appVersion) || compareVersions(rel.TagName, appVersion) <= 0 {
		upd.mu.Unlock()
		return fmt.Errorf("没有可安装的新版本")
	}
	upd.running = true
	upd.mu.Unlock()

	go func() {
		err := a.performUpdate(rel)
		upd.mu.Lock()
		upd.running = false
		upd.mu.Unlock()
		if err != nil {
			if root := portableRoot(); root != "" {
				os.RemoveAll(filepath.Join(root, "update")) // 清掉下载/解压暂存
			}
			a.addLogInternal("error", fmt.Sprintf("Update to %s failed: %v", rel.TagName, err))
			a.setUpdateProgress("error", 0, "更新失败："+err.Error())
		}
	}()
	return nil
}

func (a *App) setUpdateProgress(stage string, pct int, msg string) {
	p := UpdateProgress{Stage: stage, Percent: pct, Message: msg}
	upd.mu.Lock()
	upd.progress = p
	upd.mu.Unlock()
	if ctx := a.appCtx(); ctx != nil {
		runtime.EventsEmit(ctx, updateEvent, p)
	}
}

// ------------------------- 下载 / 校验 -------------------------

// downloadTo 下载 rawURL 到 dst，边写边算 SHA256；progress 回调下载百分比。
func (a *App) downloadTo(rawURL, dst string, size int64, progress func(int)) (string, error) {
	var lastErr error
	for _, c := range a.updateClients(15 * time.Minute) {
		sum, err := downloadWith(c, rawURL, dst, size, progress)
		if err == nil {
			return sum, nil
		}
		lastErr = err
		os.Remove(dst)
	}
	return "", lastErr
}

func downloadWith(c *http.Client, rawURL, dst string, size int64, progress func(int)) (string, error) {
	req, err := updateRequest(context.Background(), rawURL)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败：HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		size = resp.ContentLength
	}
	if size > updateMaxZipBytes {
		return "", fmt.Errorf("安装包过大（%d 字节）", size)
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 64<<10)
	lastPct := -1
	body := io.LimitReader(resp.Body, updateMaxZipBytes+1)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return "", werr
			}
			h.Write(buf[:n])
			done += int64(n)
			if done > updateMaxZipBytes {
				f.Close()
				return "", fmt.Errorf("安装包过大")
			}
			if size > 0 && progress != nil {
				if pct := int(done * 100 / size); pct != lastPct {
					lastPct = pct
					progress(pct)
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return "", rerr
		}
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fetchSmall 下载小文件（.sha256）到内存。
func (a *App) fetchSmall(rawURL string) ([]byte, error) {
	var lastErr error
	for _, c := range a.updateClients(60 * time.Second) {
		req, err := updateRequest(context.Background(), rawURL)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

var sha256HexRe = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

// parseSHA256File 从 sha256sum 格式（"<hex>  文件名"）或纯哈希文本中取出哈希。
// 有文件名时必须与 wantName 一致，防止拿错文件的校验值。
func parseSHA256File(data []byte, wantName string) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hash := sha256HexRe.FindString(line)
		if hash == "" {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[strings.Index(line, hash)+len(hash):]), "*"))
		if rest != "" && wantName != "" && !strings.EqualFold(filepath.Base(rest), wantName) {
			continue
		}
		return strings.ToLower(hash), nil
	}
	return "", fmt.Errorf("校验文件格式无效")
}

// ------------------------- 解压（防 zip-slip） -------------------------

// safeJoin 把 zip 内的相对路径接到 dest 下；拒绝绝对路径、盘符、.. 越界等任何逃出 dest 的路径。
func safeJoin(dest, name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, ":") || strings.ContainsRune(n, 0) {
		return "", fmt.Errorf("非法路径: %q", name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("非法路径: %q", name)
		}
	}
	p := filepath.Join(dest, filepath.FromSlash(n))
	rel, err := filepath.Rel(dest, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("非法路径: %q", name)
	}
	return p, nil
}

// extractUpdateZip 解压发布包到 dest，去掉公共的顶层目录（发布包内为 KNcloud/...）。
// 返回解压出的相对路径列表（正斜杠）。
func extractUpdateZip(zipPath, dest string) ([]string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("打开安装包失败: %w", err)
	}
	defer zr.Close()

	// 先按原始路径整体校验：任何条目含 ..、绝对路径或盘符都拒绝整个安装包
	//（不能先剥顶层目录再校验，否则 "../x" 会被当成顶层目录 "../" 剥掉）
	for _, f := range zr.File {
		if _, err := safeJoin(dest, strings.TrimSuffix(strings.ReplaceAll(f.Name, "\\", "/"), "/")); err != nil {
			return nil, err
		}
	}

	// 公共顶层目录
	prefix := ""
	for i, f := range zr.File {
		n := strings.ReplaceAll(f.Name, "\\", "/")
		top := n
		if j := strings.Index(n, "/"); j >= 0 {
			top = n[:j+1]
		} else {
			top = ""
		}
		if i == 0 {
			prefix = top
		} else if top != prefix {
			prefix = ""
			break
		}
	}

	var total int64
	var files []string
	for _, f := range zr.File {
		n := strings.TrimPrefix(strings.ReplaceAll(f.Name, "\\", "/"), prefix)
		if n == "" || strings.HasSuffix(n, "/") || f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("安装包含符号链接: %q", f.Name)
		}
		p, err := safeJoin(dest, n)
		if err != nil {
			return nil, err
		}
		total += int64(f.UncompressedSize64)
		if total > updateMaxUnpacked {
			return nil, fmt.Errorf("安装包解压后过大")
		}
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return nil, err
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		out, err := os.Create(p)
		if err != nil {
			rc.Close()
			return nil, err
		}
		_, cerr := io.Copy(out, io.LimitReader(rc, updateMaxUnpacked))
		rc.Close()
		if err := out.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return nil, cerr
		}
		files = append(files, n)
	}
	return files, nil
}

// ------------------------- 安装（替换文件，失败回滚） -------------------------

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

// ------------------------- 主流程 -------------------------

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

// summarizeNotes 截取更新说明（GitHub 自动生成的说明可能很长）。
func summarizeNotes(body string, max int) string {
	body = strings.TrimSpace(strings.ReplaceAll(body, "\r\n", "\n"))
	r := []rune(body)
	if len(r) <= max {
		return body
	}
	return string(r[:max]) + "…"
}
