package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ------------------------- 内核启动失败兜底 -------------------------
//
// 启动（或重启）Xray 内核失败时：
//   - 端口被占用：不自动重试（重试只会以同样的原因失败），状态里标记 CorePortError，
//     界面提示去「首选项设置」更换端口；改了端口会自动重新拉起（见 SaveSettings）；
//   - 其它错误：按 coreRetryBackoff 退避自动重试，等待期间不持有 a.mu；
//     换节点 / 手动开关或重启内核 / 退出都会让正在等待的重试作废（coreRetryGen）；
//   - 全部重试失败：停在「启动失败」状态，等用户点「重启内核」（仪表盘或托盘菜单）。
//
// 内核不在时系统代理指向一个没人监听的端口，整机断网。所以失败时（非 TUN）暂时撤下
// 系统代理、记下 sysProxyPending，内核恢复后再按原样开启。

// coreRetryBackoff 自动重试前的等待时间（第 1、2、3 次重试）。
var coreRetryBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}

// errPortInUse 内核监听端口被占用。
var errPortInUse = errors.New("port already in use")

// portInUseError startCoreLocked 端口预检失败时返回，errors.Is(err, errPortInUse) 为真。
type portInUseError struct {
	name string
	port int
}

func (e *portInUseError) Error() string {
	return fmt.Sprintf("%s port %d is already in use, please change the port in Preferences", e.name, e.port)
}

func (e *portInUseError) Is(target error) bool { return target == errPortInUse }

// looksLikePortInUse 识别监听阶段的「端口已被占用」错误（WSAEADDRINUSE / EADDRINUSE / 被系统保留的端口）。
func looksLikePortInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errPortInUse) || errors.Is(err, syscall.Errno(10048)) || errors.Is(err, syscall.Errno(10013)) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "only one usage of each socket address") ||
		strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "forbidden by its access permissions") ||
		strings.Contains(msg, "wsaeaddrinuse")
}

// noteCoreFailureLocked 记录内核启动失败（调用方持有写锁，且 coreRunning 已为 false）。
// 非 TUN 时暂时撤下系统代理，免得整机流量涌向一个没人监听的端口。
func (a *App) noteCoreFailureLocked(err error) {
	a.coreErr = err.Error()
	a.corePortErr = looksLikePortInUse(err)
	if !a.tunRunning && a.systemProxy {
		if perr := setWindowsSystemProxy(false, ""); perr == nil {
			a.systemProxy = false
			a.sysProxyPending = true
			a.addLogInternal("warn", "Core is not running: system proxy temporarily disabled, it will be restored once the core is back")
		}
	}
}

// markCoreRunningLocked 内核已成功启动（调用方持有写锁，coreRunning 已为 true）：清除失败状态；
// applyProxy 为 true 且之前因失败撤下了系统代理（或启动时没来得及开）时，按当前模式重新开启。
// TUN 运行时系统代理处于暂停状态，由 TUN 逻辑负责，这里不碰。
func (a *App) markCoreRunningLocked(applyProxy bool) {
	a.coreErr, a.corePortErr, a.coreRetrying = "", false, false
	if !applyProxy || a.tunRunning || !(a.sysProxyPending || a.systemProxy) {
		return
	}
	server := fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort)
	if err := setWindowsSystemProxy(true, server); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Failed to re-enable system proxy: %v", err))
		return
	}
	a.systemProxy = true
	a.sysProxyPending = false
	a.addLogInternal("info", fmt.Sprintf("System proxy enabled -> %s", server))
}

// handleCoreStartFailureLocked 记录失败并决定后续：端口占用只提示，其它错误安排自动重试
// （调用方持有写锁）。重试协程在锁外等待。
// toast 为 false 时不弹提示（调用方自己把错误返回给界面）。
func (a *App) handleCoreStartFailureLocked(err error, toast bool) {
	a.noteCoreFailureLocked(err)
	if a.corePortErr {
		a.coreRetrying = false
		if !toast {
			return
		}
		a.emitToast(fmt.Sprintf("内核启动失败：端口被占用（%v）。请在「首选项设置」中更换 SOCKS/HTTP 端口", err), "error")
		return
	}
	a.coreRetrying = true
	gen := a.coreRetryGen.Add(1)
	go a.coreRetryLoop(gen)
}

func (a *App) emitToast(msg, typ string) {
	if ctx := a.appCtx(); ctx != nil {
		runtime.EventsEmit(ctx, "kncloud:toast", map[string]string{"msg": msg, "type": typ})
	}
}

func (a *App) emitRefresh() {
	if ctx := a.appCtx(); ctx != nil {
		runtime.EventsEmit(ctx, "kncloud:refresh")
	}
	tray.requestRebuild()
}

// coreRetryLoop 按退避节奏重试启动内核。gen 过期（被取消）或程序退出时立即结束。
func (a *App) coreRetryLoop(gen uint64) {
	canceled := func() bool { return a.coreRetryGen.Load() != gen || a.quitting.Load() }
	for i, wait := range coreRetryBackoff {
		a.addLogInternal("info", fmt.Sprintf("Core restart attempt %d/%d in %s", i+1, len(coreRetryBackoff), wait))
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			if canceled() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !a.lockWithin(10*time.Second, canceled) {
			if canceled() {
				return
			}
			continue // 锁被长操作占着：算一次失败，继续退避
		}
		if canceled() || a.coreRunning {
			a.mu.Unlock()
			return
		}
		err := a.startCoreLocked()
		if err == nil {
			a.coreRunning = true
			a.markCoreRunningLocked(true)
			a.addLogInternal("info", fmt.Sprintf("Core recovered on retry %d", i+1))
			a.savePersisted()
			a.mu.Unlock()
			a.emitToast("内核已恢复运行", "success")
			a.emitRefresh()
			return
		}
		a.coreRunning = false
		a.noteCoreFailureLocked(err)
		a.addLogInternal("error", fmt.Sprintf("Core restart attempt %d failed: %v", i+1, err))
		if a.corePortErr {
			a.coreRetrying = false
			a.mu.Unlock()
			a.emitToast("内核启动失败：端口被占用。请在「首选项设置」中更换 SOCKS/HTTP 端口", "error")
			a.emitRefresh()
			return
		}
		a.mu.Unlock()
		a.emitRefresh()
	}
	a.mu.Lock()
	if a.coreRetryGen.Load() == gen && !a.coreRunning {
		a.coreRetrying = false
		a.addLogInternal("error", "Core failed to start after all retries; use 「重启内核」 to try again")
		a.mu.Unlock()
		a.emitToast("内核启动失败，已停止自动重试。可在仪表盘点击「重启内核」重试", "error")
		a.emitRefresh()
		return
	}
	a.mu.Unlock()
}

// RestartCore 「重启内核」：停止并重新启动内核，成功后按当前模式重新应用系统代理
// （TUN 运行时系统代理保持暂停，由 TUN 逻辑负责）。会取消正在等待的自动重试。
// 失败时返回错误：端口占用直接提示改端口，其它错误转入自动重试。
func (a *App) RestartCore() (CoreStatus, error) {
	a.coreRetryGen.Add(1)
	if !a.lockWithin(15*time.Second, a.quitting.Load) {
		return a.GetCoreStatus(), fmt.Errorf("程序正忙于其它操作，请稍后再试")
	}
	a.coreRetrying = false
	a.stopCoreLocked()
	a.coreRunning = false
	err := a.startCoreLocked()
	if err != nil {
		a.addLogInternal("error", fmt.Sprintf("Core restart failed: %v", err))
		a.handleCoreStartFailureLocked(err, false)
		port := a.corePortErr
		a.savePersisted()
		a.mu.Unlock()
		a.emitRefresh()
		if port {
			return a.GetCoreStatus(), fmt.Errorf("端口被占用，请在「首选项设置」中更换端口（%v）", err)
		}
		return a.GetCoreStatus(), fmt.Errorf("内核启动失败，正在自动重试（%v）", err)
	}
	a.coreRunning = true
	a.markCoreRunningLocked(true)
	if a.tunRunning {
		a.addLogInternal("info", "Core restarted (TUN mode: system proxy stays paused)")
	} else {
		a.addLogInternal("info", "Core restarted by user")
	}
	a.savePersisted()
	a.mu.Unlock()
	a.emitRefresh()
	return a.GetCoreStatus(), nil
}
