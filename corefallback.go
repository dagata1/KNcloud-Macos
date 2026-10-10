package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"v2rayN-win11/internal/connstate"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ------------------------- 内核常开 / 启动失败兜底 -------------------------
//
// 只要程序开着，内核就一直在跑（「直连」只是不走代理，内核照常运行）：
//   - 没有选中节点（首次登录前、节点全删光）：内核以「只有直连出站」的配置启动，
//     本地 SOCKS / HTTP 入站照样监听（startCoreLocked）；
//   - 端口被别的程序占用：启动时自动换到空闲端口并写回设置（ensureCorePortsLocked），
//     系统代理随之指向新端口；
//   - 节点配置起不来（协议桥失败、配置错误……）：立即降级为直连配置运行（coreFallback），
//     再按退避节奏重试节点配置；重试表用完仍不行就保持直连运行，等用户换节点；
//   - 启动时连直连配置都起不来：弹窗报错「内核无法启动」并退出程序（startupCoreFatal）；
//   - 运行中连直连配置都起不来（极少见）：撤下系统代理避免整机断网，然后一直重试
//     （先按重试表，之后每 connstate.SteadyCoreRetry 一次），直到内核起来或程序退出。
// 换节点 / 内部重启内核 / 退出都会让正在等待的重试作废（coreRetryGen）。

// coreRetryBackoff 自动重试前的等待时间（第 1、2、3 次重试）。
var coreRetryBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}

// coreRetrySchedule 自动重试的等待表（macOS 没有开机隐藏启动的长重试表，统一用 coreRetryBackoff）。
func (a *App) coreRetrySchedule() []time.Duration { return coreRetryBackoff }

// errPortInUse 内核监听端口被占用。
var errPortInUse = errors.New("port already in use")

// portInUseError 连自动换端口都找不到空闲端口时返回，errors.Is(err, errPortInUse) 为真。
type portInUseError struct {
	name string
	port int
}

func (e *portInUseError) Error() string {
	return fmt.Sprintf("%s port %d is already in use and no free port could be found", e.name, e.port)
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

// exiting 程序正在退出（或退出清理已跑过）：不再拉起内核。
func (a *App) exiting() bool { return a.quitting.Load() || a.cleaned.Load() }

// noteCoreFailureLocked 记录内核启动失败（调用方持有写锁）。内核完全没在运行且非 TUN 时
// 暂时撤下系统代理，免得整机流量涌向一个没人监听的端口；内核恢复后由
// markCoreRunningLocked / reapplySysProxyLocked 按原样开回。
func (a *App) noteCoreFailureLocked(err error) {
	a.coreErr = err.Error()
	a.corePortErr = looksLikePortInUse(err)
	if a.coreRunning || a.tunRunning || !a.systemProxy {
		return
	}
	if perr := setSystemProxy(false, ""); perr == nil {
		a.systemProxy = false
		a.sysProxyPending = true
		a.addLogInternal("warn", "Core is not running: system proxy temporarily disabled, it will be restored once the core is back")
	}
}

// markCoreRunningLocked 内核已以正常配置成功启动（调用方持有写锁，coreRunning 已为 true）：
// 清除失败 / 兜底状态；applyProxy 为 true 时把之前撤下的系统代理开回来。
func (a *App) markCoreRunningLocked(applyProxy bool) {
	a.coreErr, a.corePortErr, a.coreRetrying, a.coreFallback = "", false, false, false
	if applyProxy {
		a.reapplySysProxyLocked()
	}
}

// reapplySysProxyLocked 内核又在跑了：之前因故障撤下的（或启动时没来得及开的）系统代理
// 按当前端口重新开启。TUN 运行时系统代理处于暂停状态，由 TUN 逻辑负责，这里不碰。
func (a *App) reapplySysProxyLocked() {
	if !a.coreRunning || a.tunRunning || !a.sysProxyPending || a.exiting() {
		return
	}
	server := fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort)
	if err := setSystemProxy(true, server); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Failed to re-enable system proxy: %v", err))
		return
	}
	a.systemProxy = true
	a.sysProxyPending = false
	a.addLogInternal("info", fmt.Sprintf("System proxy enabled -> %s", server))
}

// fallbackToDirectLocked 节点配置起不来：改以直连配置运行内核（调用方持有写锁，内核已停）。
// 成功返回 true（coreRunning=true、coreFallback=true，失败原因保留在 coreErr）。
func (a *App) fallbackToDirectLocked(cause error) bool {
	if a.exiting() {
		return false
	}
	if err := a.startDirectCoreLocked(); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Direct-only core failed to start too: %v", err))
		return false
	}
	a.coreRunning = true
	a.coreFallback = true
	a.coreErr = cause.Error()
	a.corePortErr = looksLikePortInUse(cause)
	a.addLogInternal("warn", fmt.Sprintf("Node config could not start the core (%v); core is running direct-only until the node recovers", cause))
	a.reapplySysProxyLocked()
	return true
}

// handleCoreStartFailureLocked startCoreLocked 失败后的统一处理（调用方持有写锁）：
// 有节点就先降级为直连配置让内核继续跑，再安排自动重试；连直连都起不来就撤系统代理、一直重试。
// toast 为 false 时不弹提示（调用方自己把错误返回给界面）。
func (a *App) handleCoreStartFailureLocked(err error, toast bool) {
	a.coreRunning = false
	a.coreErr = err.Error()
	a.corePortErr = looksLikePortInUse(err)
	if a.exiting() {
		return
	}
	if a.activeNodeLocked() != nil {
		a.fallbackToDirectLocked(err)
	}
	if !a.coreRunning {
		a.noteCoreFailureLocked(err)
	}
	a.coreRetrying = true
	gen := a.coreRetryGen.Add(1)
	go a.coreRetryLoop(gen)
	if !toast {
		return
	}
	if a.coreRunning {
		a.emitToast(fmt.Sprintf("当前节点无法启动内核，已临时以直连运行，正在自动重试（%v）", err), "error")
	} else {
		a.emitToast(fmt.Sprintf("内核启动失败，正在自动重试（%v）", err), "error")
	}
}

// ensureCoreRunningLocked 内核没在运行就拉起来（调用方持有写锁）：先按当前节点（或无节点的
// 直连配置）启动，失败走 handleCoreStartFailureLocked（降级直连 + 自动重试）。
// 各种会让内核停下的路径收尾时都调用它，保证不会停在「内核没开」。
func (a *App) ensureCoreRunningLocked() {
	if a.coreRunning || a.exiting() {
		return
	}
	if err := a.startCoreLocked(); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Core start failed: %v", err))
		a.handleCoreStartFailureLocked(err, true)
		return
	}
	a.coreRunning = true
	a.markCoreRunningLocked(true)
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

// coreRetryLoop 按退避节奏重试以正常配置启动内核。gen 过期（被取消）或程序退出时立即结束。
//   - 内核完全没在运行：重试表用完后继续每 connstate.SteadyCoreRetry 重试一次，永不放弃；
//   - 内核以直连兜底运行：重试表用完就停，保持直连运行。
//
// 每次失败后立即重新降级为直连配置（startCoreLocked 会先停掉兜底实例）。
func (a *App) coreRetryLoop(gen uint64) {
	canceled := func() bool { return a.coreRetryGen.Load() != gen || a.exiting() }
	schedule := a.coreRetrySchedule()
	coreDown := true
	if a.lockWithin(10*time.Second, canceled) {
		coreDown = !a.coreRunning
		a.mu.Unlock()
	}
	for i := 0; ; i++ {
		wait, ok := connstate.CoreRetryWait(schedule, i, coreDown)
		if !ok {
			break
		}
		a.addLogInternal("info", fmt.Sprintf("Core restart attempt %d in %s", i+1, wait))
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
		if canceled() {
			a.mu.Unlock()
			return
		}
		if a.coreRunning && !a.coreFallback {
			a.coreRetrying = false // 别的路径已经把内核以正常配置拉起来了
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
			a.emitToast("内核已恢复正常运行", "success")
			a.emitRefresh()
			return
		}
		a.coreRunning = false
		a.addLogInternal("error", fmt.Sprintf("Core restart attempt %d failed: %v", i+1, err))
		a.coreErr = err.Error()
		a.corePortErr = looksLikePortInUse(err)
		if a.activeNodeLocked() != nil {
			a.fallbackToDirectLocked(err)
		}
		if !a.coreRunning {
			a.noteCoreFailureLocked(err)
		}
		coreDown = !a.coreRunning
		a.mu.Unlock()
		a.emitRefresh()
	}
	// 只有「直连兜底在跑、节点仍起不来」才会走到这里
	a.mu.Lock()
	if a.coreRetryGen.Load() == gen && a.coreFallback {
		a.coreRetrying = false
		a.addLogInternal("error", "Node still cannot start the core after all retries; core stays running direct-only. Pick another node")
		a.mu.Unlock()
		a.emitToast("当前节点仍无法启动内核，内核保持直连运行。可换个节点", "error")
		a.emitRefresh()
		return
	}
	a.mu.Unlock()
}

// RestartCore 停止并重新启动内核（界面已无按钮，仅供换节点 / 更新回滚等内部路径调用）：停止并重新启动内核，成功后按当前模式重新应用系统代理
// （TUN 运行时系统代理保持暂停，由 TUN 逻辑负责）。会取消正在等待的自动重试。
// 失败时内核降级为直连配置继续运行（或一直重试），并把原因返回给界面。
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
		fallback := a.coreRunning
		a.savePersisted()
		a.mu.Unlock()
		a.emitRefresh()
		if fallback {
			return a.GetCoreStatus(), fmt.Errorf("当前节点无法启动内核，已临时以直连运行，正在自动重试（%v）", err)
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

// startupCoreFatal 启动时内核（含直连兜底配置）完全起不来：弹窗报错后退出程序。
// 内核是程序的核心，起不来就没有继续运行的意义，不再在后台无限重试。
func (a *App) startupCoreFatal(err error) {
	a.coreRetryGen.Add(1) // 取消已安排的自动重试
	a.addLogInternal("error", fmt.Sprintf("Core cannot start, exiting: %v", err))
	if ctx := a.appCtx(); ctx != nil {
		runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
			Type:    runtime.ErrorDialog,
			Title:   "KNcloud 无法启动",
			Message: fmt.Sprintf("内核无法启动，程序将退出。\n\n原因：%v", err),
		})
	}
	a.quitApp()
}
