// Package updfetch 应用内更新的网络请求：检查更新（GitHub API）、下载发布 zip 与 .sha256。
//
// 与订阅相同，一律经本程序的本地 HTTP 代理（内核常开，分流 / 直连由内核按当前路由模式决定），
// 不看路由模式、不直连兜底。内核正在重启时先等本地端口起来（subfetch.WaitPort，最多 opt.Wait），
// 每个请求都重新取一次端口，内核换了端口也能跟上。纯标准库，可在 Linux 上跑单测。
package updfetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	"v2rayN-win11/internal/subfetch"
)

// Request 一次 GET。
type Request struct {
	URL       string
	UserAgent string
	Accept    string // 可空
	MaxBytes  int64  // 响应体上限
}

// HTTPStatusError 服务器返回了非 200。
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

func newReq(ctx context.Context, r Request) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, err
	}
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	return req, nil
}

// Get 经本地代理 GET 小内容（发布信息 JSON、.sha256）。非 200 返回 *HTTPStatusError。
func Get(r Request, opt subfetch.Options) ([]byte, error) {
	client, err := subfetch.NewClient(opt)
	if err != nil {
		return nil, err
	}
	req, err := newReq(context.Background(), r)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, r.MaxBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{Code: resp.StatusCode}
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ErrTooLarge 安装包超过上限。
type ErrTooLarge struct{ Size int64 }

func (e *ErrTooLarge) Error() string { return fmt.Sprintf("安装包过大（%d 字节）", e.Size) }

// Download 经本地代理下载 r.URL 到 dst，边写边算 SHA256（小写 hex）。size 为预期大小
// （Content-Length 优先），用于算进度；progress 可空。失败时删除 dst。
func Download(r Request, dst string, size int64, opt subfetch.Options, progress func(int)) (string, error) {
	sum, err := download(r, dst, size, opt, progress)
	if err != nil {
		os.Remove(dst)
	}
	return sum, err
}

func download(r Request, dst string, size int64, opt subfetch.Options, progress func(int)) (string, error) {
	client, err := subfetch.NewClient(opt)
	if err != nil {
		return "", err
	}
	req, err := newReq(context.Background(), r)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败：%w", &HTTPStatusError{Code: resp.StatusCode})
	}
	if resp.ContentLength > 0 {
		size = resp.ContentLength
	}
	if r.MaxBytes > 0 && size > r.MaxBytes {
		return "", &ErrTooLarge{Size: size}
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 64<<10)
	lastPct := -1
	var body io.Reader = resp.Body
	if r.MaxBytes > 0 {
		body = io.LimitReader(resp.Body, r.MaxBytes+1)
	}
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return "", werr
			}
			h.Write(buf[:n])
			done += int64(n)
			if r.MaxBytes > 0 && done > r.MaxBytes {
				f.Close()
				return "", &ErrTooLarge{Size: done}
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
