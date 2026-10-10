// Package connstate 决定「上次的连接状态」如何记录、启动时如何恢复，以及开机时的重试节奏。
// 纯逻辑，不依赖 Windows API，可在 Linux 上跑单测；调用方在主包 connrestore.go。
package connstate

import "time"

// 持久化在 config.json 的 lastConn 字段里的取值。
const (
	Off   = "off"   // 旧版本：用户主动断开。内核现在常开，启动时按「仅内核」恢复（系统代理不开）
	Core  = "core"  // 内核运行、系统代理关闭（用户自己配 SOCKS/HTTP 端口用）
	Proxy = "proxy" // 内核运行 + 系统代理（默认，也是旧版本「启动即连接」的行为）
	Tun   = "tun"   // TUN 接管整机流量
)

// Normalize 规整持久化值。旧配置没有该字段（空串）或值不认识时按 Proxy 处理，
// 与旧版本「启动即自动开启内核与系统代理」保持一致。
func Normalize(s string) string {
	switch s {
	case Off, Core, Proxy, Tun:
		return s
	}
	return Proxy
}

// Plan 启动时要恢复的动作。
type Plan struct {
	StartCore   bool
	SystemProxy bool
	Tun         bool
}

// PlanFor 根据上次状态给出恢复计划。内核常开：任何状态（包括旧版本记下的 off）都启动内核，
// off 只是不开系统代理。TUN 也先开系统代理：TUN 起来后会把它暂停并记住，
// 用户以后关 TUN 时按原样恢复成系统代理模式（与手动先连接再开 TUN 的流程一致）。
func PlanFor(state string) Plan {
	switch Normalize(state) {
	case Off, Core:
		return Plan{StartCore: true}
	case Tun:
		return Plan{StartCore: true, SystemProxy: true, Tun: true}
	default:
		return Plan{StartCore: true, SystemProxy: true}
	}
}

// Snapshot 计算当前状态所需的运行时字段。
type Snapshot struct {
	TunRunning      bool
	TunWanted       bool // 开机正在（或曾经）尝试恢复 TUN、用户还没改过连接方式
	CoreRunning     bool
	CoreFailed      bool // 内核因故障没在运行（不是用户主动停的）
	SystemProxy     bool
	SysProxyPending bool // 内核故障期间暂时撤下的系统代理，恢复后会重新开
}

// Current 由运行时状态推出应持久化的连接状态。
// 内核因故障暂时没在运行（重试中 / 重试用尽）时沿用上次的值：一次开机网络没就绪
// 不能把「已连接」的意图冲掉，否则下次开机就不再自动连接了。
func Current(prev string, s Snapshot) string {
	switch {
	case s.TunRunning || s.TunWanted:
		return Tun
	case s.CoreRunning:
		if s.SystemProxy || s.SysProxyPending {
			return Proxy
		}
		return Core
	case s.CoreFailed:
		return Normalize(prev)
	default:
		return Off
	}
}

// TunRestoreSchedule 开机恢复 TUN 时每次尝试前的等待：第一次立即尝试，之后逐步拉长，
// 累计约 5 分钟。TUN 需要解析节点域名、找到物理出口网卡，开机时网络没就绪会失败。
var TunRestoreSchedule = []time.Duration{
	0, 3 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second,
	30 * time.Second, 30 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second,
}

// BootCoreRetrySchedule 开机自启后的前几分钟内核启动失败时的重试间隔（比平时的 2/5/15 秒更耐心）。
var BootCoreRetrySchedule = []time.Duration{
	2 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second,
	30 * time.Second, 30 * time.Second, 60 * time.Second, 60 * time.Second,
}

// SteadyCoreRetry 重试表用完后内核仍完全没有运行（连直连兜底配置都起不来）时的固定重试间隔：
// 内核必须常开，所以这种情况一直重试下去，直到起来或程序退出。
const SteadyCoreRetry = 60 * time.Second

// CoreRetryWait 第 i 次（从 0 起）自动重试前的等待。
//   - i 在重试表内：按表等待；
//   - 重试表用完、内核完全没在运行（coreDown）：以 SteadyCoreRetry 无限重试；
//   - 重试表用完、内核已以直连兜底配置运行：停止重试（ok=false），等用户换节点或手动重启。
func CoreRetryWait(schedule []time.Duration, i int, coreDown bool) (wait time.Duration, ok bool) {
	if i < len(schedule) {
		return schedule[i], true
	}
	if coreDown {
		return SteadyCoreRetry, true
	}
	return 0, false
}

// Total 返回一个重试表的累计等待时长。
func Total(schedule []time.Duration) time.Duration {
	var t time.Duration
	for _, d := range schedule {
		t += d
	}
	return t
}
