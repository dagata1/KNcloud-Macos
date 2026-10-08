package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	xcore "github.com/xtls/xray-core/core"
)

type NodeItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // VMess, VLESS, Trojan, Shadowsocks（Hysteria2 仅解析，Xray 不支持）
	Address  string `json:"address"`
	Port     int    `json:"port"`
	UUID     string `json:"uuid"`
	Security string `json:"security"` // tls, reality, none
	Network  string `json:"network"`  // tcp, ws, grpc, udp
	Delay    int    `json:"delay"`    // ms: -1 untried, -2 timeout, >0 latency
	Active   bool   `json:"active"`
	Group    string `json:"group"`
	Upload   string `json:"upload"`
	Download string `json:"download"`

	// 扩展字段（用于真实内核配置生成）
	SubID       string `json:"subId,omitempty"`
	AlterID     int    `json:"alterId,omitempty"`
	Flow        string `json:"flow,omitempty"`
	SNI         string `json:"sni,omitempty"`
	PBK         string `json:"pbk,omitempty"`
	SID         string `json:"sid,omitempty"`
	FP          string `json:"fp,omitempty"`
	Path        string `json:"path,omitempty"`
	HostName    string `json:"hostName,omitempty"`
	ServiceName string `json:"serviceName,omitempty"`
	Method      string `json:"method,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"` // 跳过 TLS 证书校验（分享链接里的 insecure=1 / allowInsecure=1）
}

// SubscriptionItem.URL 订阅地址内含 token，敏感度与登录凭证相当：带 json:"-" 不下发前端
// （前端从不读取），持久化由 persistedConfig.SubscriptionURLs 按 ID 单独加密存取（见 config.go）。
type SubscriptionItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"-"`
	NodeCount int    `json:"nodeCount"`
	UpdatedAt string `json:"updatedAt"`
	AutoCheck bool   `json:"autoCheck"`
}

type CoreStatus struct {
	Running         bool   `json:"running"`
	CoreType        string `json:"coreType"`
	CoreVersion     string `json:"coreVersion"`
	SystemProxy     bool   `json:"systemProxy"`
	RoutingMode     string `json:"routingMode"` // bypass-cn, global, direct
	UpSpeed         string `json:"upSpeed"`
	DownSpeed       string `json:"downSpeed"`
	TotalUp         string `json:"totalUp"`
	TotalDown       string `json:"totalDown"`
	ActiveNodeName  string `json:"activeNodeName"`
	ActiveNodeProto string `json:"activeNodeProto"`
	SocksPort       int    `json:"socksPort"`
	HttpPort        int    `json:"httpPort"`
	TunRunning      bool   `json:"tunRunning"`
	TunnelMode      bool   `json:"tunnelMode"`
	// Busy 为 true 表示有耗时操作（开关 TUN、切换策略）正在进行，其余字段是操作前的快照
	Busy bool `json:"busy"`
}

type LogItem struct {
	ID      int64  `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"` // info, warn, error
	Message string `json:"message"`
}

type AppSettings struct {
	Theme      string `json:"theme"`  // system, light, dark
	UiMode     string `json:"uiMode"` // classic(普通模式), simple(简易模式)
	SocksPort  int    `json:"socksPort"`
	HttpPort   int    `json:"httpPort"`
	AutoStart  bool   `json:"autoStart"`
	AllowLan   bool   `json:"allowLan"`
	MuxEnabled bool   `json:"muxEnabled"`
	CoreType   string `json:"coreType"`
	DnsServers string `json:"dnsServers"`
	// MinimizeToTray 为 true 时，点窗口关闭按钮只收进托盘，程序继续后台运行；
	// 真正退出需要走托盘菜单的「退出」。
	MinimizeToTray bool `json:"minimizeToTray"`
	// SubUpdateHours 自动更新订阅：-1 = 关闭，其余（含旧版本的 1/3/6/12/24）= 每周一次。
	SubUpdateHours int `json:"subUpdateHours"`
}

type App struct {
	ctx               context.Context
	mu                sync.RWMutex
	nodes             []NodeItem
	subscriptions     []SubscriptionItem
	logMu             sync.Mutex // 单独保护 logs / logIDCounter：日志会被托盘、测速等
	logs              []LogItem  // 未持 a.mu 的 goroutine 写入，不能共用 a.mu
	logIDCounter      int64
	settings          AppSettings
	coreRunning       bool
	systemProxy       bool
	routingMode       string
	activeNodeID      string
	traffic           trafficMeter               // 经代理节点的流量统计（独立锁，见 traffic.go）
	statsInst         statsInstHolder            // 当前内核实例（采样协程无锁读取）
	traySubUpdating   atomic.Bool                // 托盘「更新订阅」进行中
	subLastAuto       atomic.Int64               // 上次成功更新订阅的 Unix 时间（自动更新判定用）
	statusCache       atomic.Pointer[CoreStatus] // GetCoreStatus 上次拿到锁时的快照（长操作期间返回它）
	xrayInst          *xcore.Instance
	coreNodeID        string // 内核 proxy 出站当前实际指向的节点 ID（热切换/回滚判断用）
	tunRunning        bool
	tunIfaceIdx       uint32
	tap               *tapForwarder // tapstack.go：Go 重写的 SSTap 核心（常驻网卡 + gvisor 转发），TUN 主路径
	nativeTunCmd      *exec.Cmd     // C/lwIP tun2socks helper, SSTap-compatible fast path
	nativeTunDone     chan struct{}
	tapDnsHijacked    bool           // 是否给 TUN 网卡设置过劫持 DNS（停止时需复位）
	tunRt             *tunRouteState // TUN 写入系统的全部 IPv4 路由记账（差量同步，见 tunroutes.go）
	tunOps            routeOps       // 路由操作实现；nil 表示 Windows IP Helper（单测注入 fake）
	tunPhys           physHop        // TUN 开启时的默认物理出口（绕过网段用）
	tunEgressIface    string         // TUN 开启时的物理网卡名：Xray 出站 sockopt.interface 绑定它；空表示 TUN 未接管
	tunUDPPort        int            // TUN 开启时 UDP 专用（不嗅探）SOCKS 入站端口；0 = 未启用
	tunDNSGuard       *tunDNSGuard   // TUN 开启时拦截发往物理网卡 DNS 的查询（WFP 动态会话）
	tunV6             bool           // 是否写过 2000::/3 防泄漏路由
	tunPausedSysProxy bool           // TUN 开启时暂停了 Windows 系统代理，关 TUN 时恢复
	autoPing          autoPinger     // 后台自动测速（autoping.go）
	account           AccountInfo
	quitting          bool             // true 表示用户已确认退出（托盘菜单「退出」），关闭窗口不再拦截
	cleaned           bool             // true 表示已执行退出清理，避免 beforeClose 与 quitApp 兜底重复执行
	webLogin          *webLoginManager // 网页授权登录的本地回调服务（见 weblogin.go）；用指针避免拷贝内部互斥锁
}

func NewApp() *App {
	app := &App{
		coreRunning:  false,
		systemProxy:  getWindowsSystemProxy(),
		routingMode:  "bypass-cn",
		activeNodeID: "",
		settings: AppSettings{
			Theme:      "dark",
			UiMode:     "classic",
			SocksPort:  10808,
			HttpPort:   10809,
			AutoStart:  true,
			AllowLan:   false,
			MuxEnabled: true,
			CoreType:   "Xray-core",
			DnsServers: "1.1.1.1, 8.8.8.8, 223.5.5.5",

			MinimizeToTray: true,
		},
		nodes:         []NodeItem{},
		subscriptions: []SubscriptionItem{},
	}

	app.account = defaultAccount()

	loaded := app.loadPersisted()
	if loaded {
		app.addLogInternal("info", "KNcloud-WIN restored local configuration from disk")
	} else {
		app.addLogInternal("info", "KNcloud-WIN first run: empty node list, add nodes or sync a subscription to start")
		app.savePersisted()
	}
	// 历史版本首次运行会写入 3 个「内置示例」演示节点（假节点，不可用）。
	// 只按本程序自己的分组标记清理，不碰用户自建或订阅来的节点。
	removedSamples := 0
	activeRemoved := false
	var kept []NodeItem
	for _, n := range app.nodes {
		if n.Group == "内置示例" {
			activeRemoved = activeRemoved || n.Active
			removedSamples++
			continue
		}
		kept = append(kept, n)
	}
	if removedSamples > 0 {
		app.nodes = kept
		if activeRemoved {
			app.activeNodeID = ""
			for i := range app.nodes {
				app.nodes[i].Active = false
			}
			if len(app.nodes) > 0 {
				app.nodes[0].Active = true
				app.activeNodeID = app.nodes[0].ID
			}
		}
		app.addLogInternal("info", fmt.Sprintf("Removed %d built-in sample node(s) left by a previous version", removedSamples))
		app.savePersisted()
	}
	if n := removeLegacySingBoxFiles(); n > 0 {
		app.addLogInternal("info", fmt.Sprintf("Removed %d legacy sing-box file(s) from the config directory", n))
	}
	app.addLogInternal("info", fmt.Sprintf("Core component Xray-core %s loaded", xrayCoreVersion()))
	return app
}

// addLogInternal 追加一条日志。内部自己加锁（logMu），因此调用方无论是否持有
// a.mu 都可以安全调用 —— 托盘菜单、并发测速等 goroutine 都会走到这里。
func (a *App) addLogInternal(level, message string) {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	a.logIDCounter++
	item := LogItem{
		ID:      a.logIDCounter,
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
		Message: message,
	}
	a.logs = append(a.logs, item)
	if len(a.logs) > 500 {
		a.logs = a.logs[len(a.logs)-500:]
	}
}

func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()

	// 开机自启：以持久化设置为准同步注册表 Run 键（首次运行默认开启；
	// 程序换了安装路径也会在这里把自启项更新到新 exe）。需在托盘构建前执行，
	// 这样托盘菜单的勾选状态与设置页一致。
	if err := setAutoStart(a.settings.AutoStart); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Sync auto-start failed: %v", err))
	}

	// 注册 kncloud:// 协议，网页「一键订阅」可直接拉起客户端登录并导入订阅
	if err := registerURLProtocol(); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Register kncloud:// protocol failed: %v", err))
	}

	// 系统托盘：右下角常驻图标 + 右键菜单
	startTray(a)

	// 真实内核流量统计轮询：每秒采样一次 proxy 出站计数器（只算经节点的流量，见 traffic.go）
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				a.sampleTraffic()
			}
		}
	}()

	// 定时自动更新订阅（套餐/流量 + 节点），间隔见设置 subUpdateHours
	go a.subAutoUpdateLoop()

	// 登录过官网账户：启动时自动同步订阅节点
	go func() {
		time.Sleep(2 * time.Second)
		a.mu.RLock()
		loggedIn := a.account.LoggedIn
		subID := a.account.SubID
		a.mu.RUnlock()
		synced := false
		// 每周才更新一次订阅：启动时只在距上次更新已满一周（或从未更新过）时同步
		a.mu.RLock()
		interval := subUpdateInterval(a.settings.SubUpdateHours)
		a.mu.RUnlock()
		last := a.subLastAuto.Load()
		startupDue := interval > 0 && (last <= 0 || time.Since(time.Unix(last, 0)) >= interval)
		if loggedIn && subID != "" && startupDue {
			a.weeklyResolveDomain(time.Now())
			if err := a.refreshSubscription(subID); err == nil {
				synced = true // refreshSubscription 成功时已触发自动测速
				// 同步完成后通知前端刷新，避免前端停留在「无节点 / 连接失败」状态
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "kncloud:refresh")
				}
			}
		}
		// 没有订阅或同步失败：仍对本地已有节点做一轮启动测速
		if !synced {
			a.requestAutoPing()
		}
	}()

	// 启动即自动开启内核与系统代理（用户无需手动操作）
	go func() {
		a.mu.Lock()
		if err := a.startCoreLocked(); err != nil {
			a.coreRunning = false
			a.addLogInternal("error", fmt.Sprintf("Auto-start core failed: %v", err))
			a.mu.Unlock()
			return
		}
		a.coreRunning = true

		server := fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort)
		if err := setWindowsSystemProxy(true, server); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to auto-enable system proxy: %v", err))
		} else {
			a.systemProxy = true
			a.addLogInternal("info", fmt.Sprintf("System proxy auto-enabled -> %s", server))
		}
		a.savePersisted()
		a.mu.Unlock()
	}()
}

func formatSpeed(bytesPerSec int64) string {
	bps := float64(bytesPerSec)
	if bps < 1024 {
		return fmt.Sprintf("%d B/s", bytesPerSec)
	} else if bps < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", bps/1024.0)
	} else if bps < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB/s", bps/(1024.0*1024.0))
	}
	return fmt.Sprintf("%.2f GB/s", bps/(1024.0*1024.0*1024.0))
}

func formatBytes(bytes int64) string {
	b := float64(bytes)
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", b/1024.0)
	} else if b < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", b/(1024.0*1024.0))
	} else if b < 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", b/(1024.0*1024.0*1024.0))
	}
	return fmt.Sprintf("%.2f TB", b/(1024.0*1024.0*1024.0*1024.0))
}

// ------------------------- Node APIs -------------------------

func (a *App) GetNodes() []NodeItem {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]NodeItem, len(a.nodes))
	copy(out, a.nodes)
	return out
}

func (a *App) SelectNode(id string) (NodeItem, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 先定位节点再改动任何状态：找不到时不应把现有选择清空。
	var selected NodeItem
	found := false
	for i := range a.nodes {
		if a.nodes[i].ID == id {
			selected = a.nodes[i]
			found = true
			break
		}
	}
	if !found {
		return selected, fmt.Errorf("node not found")
	}

	// 记下切换前的节点，切换失败时据此回滚，避免把用户钉在一个连不上的节点上
	// （activeNodeID 会落盘，重启后也会自动恢复该节点）。
	prevID := a.activeNodeID
	wasCoreRunning := a.coreRunning
	a.setActiveNodeLocked(id)
	selected.Active = true

	a.addLogInternal("info", fmt.Sprintf("Primary route switched to node: [%s] %s (%s:%d)", selected.Protocol, selected.Name, selected.Address, selected.Port))

	// 换节点必须让「出口 IP」立刻改变：
	//  - TUN 在跑：走完整切换（停转发 → 热切换出站 → 清 DNS 缓存 → 重铺路由 → 拉起转发）。
	//    存量 TCP/keep-alive 连接挂在旧节点上不会自己迁移，只重铺路由是不够的；
	//    停转发会拆掉 TUN 上的全部连接。
	//  - 仅系统代理：热切换 proxy 出站（入站监听不断、新请求走新节点），
	//    热切换不可用时回退为整体重启内核；同样要清 DNS 缓存。
	var err error
	if a.tunRunning {
		err = a.tunHardSwitchLocked(selected)
		if err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to switch node in TUN mode: %v", err))
			if !errors.Is(err, errNodeRejected) {
				// 切换失败则 TUN 已处于半拆状态，直接软停让流量回到直连，
				// 避免留下「界面显示新节点、实际无隧道」的错配状态。
				a.tunSoftStopLocked()
			}
		}
	} else if a.coreRunning {
		err = a.switchCoreNodeLocked(selected)
		if err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to switch core to the new node: %v", err))
		} else {
			// 清 DNS 缓存，否则检测站可能继续命中旧节点的解析结果。
			flushDnsClientCache()
		}
	}
	if err != nil {
		a.rollbackNodeSelectionLocked(prevID, id, wasCoreRunning)
		a.savePersisted()
		selected.Active = false
		return selected, err
	}
	a.savePersisted()
	return selected, nil
}

// setActiveNodeLocked 把 id 标为唯一的 Active 节点（调用方需持有写锁）。
func (a *App) setActiveNodeLocked(id string) {
	for i := range a.nodes {
		a.nodes[i].Active = a.nodes[i].ID == id
	}
	a.activeNodeID = id
}

// rollbackNodeSelectionLocked 换节点失败后恢复到切换前的节点（调用方需持有写锁）。
//
//   - 选择状态（Active / activeNodeID）一律退回旧节点；
//   - 内核若因整体重启失败而停掉，尽力用旧节点重新拉起；
//   - 内核仍在跑但可能已换到新节点（TUN 硬切换在出站替换之后的步骤失败），
//     尽力把出站切回旧节点，保证「界面显示的节点」与「内核实际出口」一致。
//
// TUN 本身不在此恢复：沿用原有语义，失败即软停回直连，由用户重新开启。
func (a *App) rollbackNodeSelectionLocked(prevID, failedID string, wasCoreRunning bool) {
	if prevID == "" || prevID == failedID {
		return
	}
	var prev *NodeItem
	for i := range a.nodes {
		if a.nodes[i].ID == prevID {
			prev = &a.nodes[i]
			break
		}
	}
	if prev == nil {
		return
	}
	a.setActiveNodeLocked(prevID)
	prevNode := *prev
	a.addLogInternal("warn", fmt.Sprintf("Node switch failed, reverted selection to [%s] %s", prevNode.Protocol, prevNode.Name))

	switch {
	case wasCoreRunning && !a.coreRunning:
		if err := a.startCoreLocked(); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to restore core on previous node: %v", err))
			return
		}
		a.coreRunning = true
		a.addLogInternal("info", fmt.Sprintf("Core restored on previous node: %s", prevNode.Name))
	case a.coreRunning && a.coreNodeID != "" && a.coreNodeID != prevID:
		if err := a.switchCoreNodeLocked(prevNode); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to switch core back to previous node: %v", err))
		}
	}
}

// switchCoreNodeLocked 让正在运行的内核改走 node（调用方需持有写锁，且 node 已置为 Active）。
//
// 优先热切换 proxy 出站：入站监听保留，本机应用和 TUN 转发不会在切换瞬间被拒连。
// 只有热切换「不可用」时才回退整体重启；新节点本身有问题时现网出站原样保留，
// 直接把错误交给调用方回滚，而不是重启一个注定失败的内核。
func (a *App) switchCoreNodeLocked(node NodeItem) error {
	err := a.hotSwapProxyOutboundLocked(node)
	if err == nil {
		a.coreNodeID = node.ID
		a.addLogInternal("info", fmt.Sprintf("Switched outbound to [%s] %s without restarting the core", node.Protocol, node.Name))
		return nil
	}
	if !errors.Is(err, errHotSwapUnavailable) {
		return err
	}
	a.addLogInternal("warn", fmt.Sprintf("Hot switch unavailable (%v), restarting core", err))
	return a.restartCoreLocked()
}

// restartCoreLocked 以当前 Active 节点整体重启内核（调用方需持有写锁）。
// 失败时内核已停，coreRunning 置 false。
func (a *App) restartCoreLocked() error {
	if err := a.startCoreLocked(); err != nil {
		a.coreRunning = false
		return fmt.Errorf("restart core: %w", err)
	}
	return nil
}

func (a *App) AddNode(node NodeItem) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if node.ID == "" {
		node.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	if node.Name == "" {
		node.Name = fmt.Sprintf("%s:%d", node.Address, node.Port)
	}
	if node.Group == "" {
		node.Group = "Custom"
	}
	if node.Delay == 0 {
		node.Delay = -1
	}
	a.nodes = append(a.nodes, node)
	a.addLogInternal("info", fmt.Sprintf("Node added: %s (%s:%d)", node.Name, node.Address, node.Port))
	a.savePersisted()
	return nil
}

func (a *App) ImportNodesFromLinks(links string) (int, error) {
	nodes, skipped := ParseShareLinksReport(links)
	if msg := skippedLinksLog(skipped); msg != "" {
		a.addLogInternal("warn", msg)
	}
	if len(nodes) == 0 {
		return 0, fmt.Errorf("no valid share links found (supported: vmess/vless/trojan/ss)")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range nodes {
		nodes[i].ID = fmt.Sprintf("node-%d", time.Now().UnixNano()+int64(i))
		if nodes[i].Group == "" {
			nodes[i].Group = "Custom"
		}
		a.nodes = append(a.nodes, nodes[i])
	}
	a.addLogInternal("info", fmt.Sprintf("Imported %d nodes from share links", len(nodes)))
	a.savePersisted()
	return len(nodes), nil
}

// UpdateNode 编辑已有节点；保留 ID / 活动状态 / 订阅归属，重置测速结果。
func (a *App) UpdateNode(node NodeItem) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx := -1
	for i := range a.nodes {
		if a.nodes[i].ID == node.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("node not found")
	}

	old := a.nodes[idx]
	node.ID = old.ID
	node.Active = old.Active
	node.SubID = old.SubID
	node.Delay = -1
	if node.Name == "" {
		node.Name = fmt.Sprintf("%s:%d", node.Address, node.Port)
	}
	if node.Group == "" {
		node.Group = old.Group
	}
	a.nodes[idx] = node
	a.addLogInternal("info", fmt.Sprintf("Node updated: %s (%s:%d)", node.Name, node.Address, node.Port))

	// 编辑的是当前活动节点 → 走完整切换，让存量连接一并断开、出口立即改变。
	// （原先这里只重铺路由，挂在旧参数上的连接会继续用旧出口。）
	if old.Active && a.tunRunning {
		if err := a.tunHardSwitchLocked(node); err != nil {
			if errors.Is(err, errNodeRejected) {
				// 新参数被拒绝：隧道与内核仍在旧参数上正常工作 —— 撤回这次编辑，
				// 保证界面与实际出口一致，不软停 TUN。
				a.nodes[idx] = old
				a.addLogInternal("error", fmt.Sprintf("Node edit rejected in TUN mode, kept previous settings: %v", err))
				return err
			}
			a.tunSoftStopLocked()
			a.addLogInternal("error", fmt.Sprintf("Failed to apply node edit in TUN mode: %v", err))
			a.savePersisted()
			return err
		}
	} else if old.Active && a.coreRunning {
		if err := a.startCoreLocked(); err != nil {
			a.coreRunning = false
			a.addLogInternal("error", fmt.Sprintf("Failed to restart core after node edit: %v", err))
		} else {
			flushDnsClientCache()
		}
	}
	a.savePersisted()
	tray.requestRebuild()
	return nil
}

func (a *App) DeleteNodes(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	idMap := make(map[string]bool, len(ids))
	for _, id := range ids {
		idMap[id] = true
	}

	wasActive := false
	var updated []NodeItem
	deletedCount := 0
	for _, n := range a.nodes {
		if idMap[n.ID] {
			if n.Active {
				wasActive = true
			}
			deletedCount++
			continue
		}
		updated = append(updated, n)
	}
	a.nodes = updated

	if wasActive {
		a.activeNodeID = ""
		var next *NodeItem
		if len(a.nodes) > 0 {
			a.nodes[0].Active = true
			a.activeNodeID = a.nodes[0].ID
			next = &a.nodes[0]
		}
		if !a.tunRunning {
			// 没用 TUN：内核是唯一出口，活动节点没了就停内核，等用户重选。
			if a.coreRunning {
				a.stopCoreLocked()
				a.coreRunning = false
				a.addLogInternal("warn", "Active node deleted, core stopped; select a node and start again")
			}
		} else if next != nil {
			// TUN 在跑：依次尝试剩余节点。被拒绝（errNodeRejected）的节点不影响隧道，
			// 继续试下一个；只有真正拆坏了隧道或一个能用的都没有时才软停。
			switched := false
			var lastErr error
			for i := range a.nodes {
				cand := a.nodes[i]
				a.setActiveNodeLocked(cand.ID)
				err := a.tunHardSwitchLocked(cand)
				if err == nil {
					switched = true
					a.addLogInternal("info", fmt.Sprintf("Active node deleted, switched to [%s] %s", cand.Protocol, cand.Name))
					break
				}
				lastErr = err
				a.addLogInternal("warn", fmt.Sprintf("Surviving node %s rejected in TUN mode: %v", cand.Name, err))
				if !errors.Is(err, errNodeRejected) {
					break
				}
			}
			if !switched {
				a.tunSoftStopLocked()
				a.addLogInternal("error", fmt.Sprintf("Failed to switch TUN to a surviving node after deletion, TUN stopped: %v", lastErr))
			}
		} else {
			// 一个节点都不剩，没有任何东西可以代理 —— 只能停。
			a.stopCoreLocked()
			a.coreRunning = false
			a.tunSoftStopLocked()
			a.addLogInternal("warn", "Active node deleted and no nodes left, TUN stopped")
		}
	}
	a.addLogInternal("warn", fmt.Sprintf("Removed %d nodes", deletedCount))
	a.savePersisted()
	tray.requestRebuild()
	return nil
}

func (a *App) DeleteNode(id string) error {
	return a.DeleteNodes([]string{id})
}

func (a *App) PingNode(id string) int {
	return a.pingNode(id, false)
}

// pingNode 真连接测速单个节点并回写延迟；quiet 时不逐个写日志（后台自动测速用，避免刷屏）。
func (a *App) pingNode(id string, quiet bool) int {
	a.mu.RLock()
	var target NodeItem
	found := false
	for _, n := range a.nodes {
		if n.ID == id {
			target = n
			found = true
			break
		}
	}
	// TUN 接管时测速出站绑物理网卡，不经当前节点绕一圈（见 realDelayTestConfig）
	egress := a.tunEgressIface
	a.mu.RUnlock()

	if !found {
		return -2
	}

	// 真连接测速：经该节点完整代理链路请求测速 URL
	latency := testNodeRealDelay(target, egress)

	a.mu.Lock()
	for i := range a.nodes {
		if a.nodes[i].ID == id {
			a.nodes[i].Delay = latency
			break
		}
	}
	a.mu.Unlock()

	// 实时推送当前节点的真连接测速结果给前端，实现先测完先显示
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "kncloud:node-delay", map[string]interface{}{
			"id":    id,
			"delay": latency,
		})
	}

	if quiet {
		return latency
	}
	if latency == -2 {
		a.addLogInternal("warn", fmt.Sprintf("Real-connection test failed for node [%s] (timeout or unreachable)", target.Name))
	} else {
		a.addLogInternal("info", fmt.Sprintf("Real-connection test for node [%s]: %d ms", target.Name, latency))
	}
	return latency
}

// pingConcurrency 同时运行的测速临时 Xray 实例上限（每个实例约十几 MB 内存、一条到节点的连接）
const pingConcurrency = 4

// pingIDs 并发测速给定节点（最多 pingConcurrency 个同时进行），返回测通的个数。
func (a *App) pingIDs(ids []string, quiet bool) int {
	var wg sync.WaitGroup
	var ok atomic.Int32
	sem := make(chan struct{}, pingConcurrency)
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(nodeID string) {
			defer wg.Done()
			defer func() { <-sem }()
			if a.pingNode(nodeID, quiet) > 0 {
				ok.Add(1)
			}
		}(id)
	}
	wg.Wait()
	return int(ok.Load())
}

func (a *App) PingNodes(ids []string) []NodeItem {
	if len(ids) == 0 {
		return a.GetNodes()
	}
	idMap := make(map[string]bool, len(ids))
	for _, id := range ids {
		idMap[id] = true
	}

	a.mu.RLock()
	var targets []string
	for _, n := range a.nodes {
		if idMap[n.ID] {
			targets = append(targets, n.ID)
		}
	}
	a.mu.RUnlock()

	if len(targets) == 0 {
		return a.GetNodes()
	}

	a.pingIDs(targets, false)

	a.addLogInternal("info", fmt.Sprintf("Real-connection latency test completed for %d selected nodes", len(targets)))
	return a.GetNodes()
}

func (a *App) PingAllNodes() []NodeItem {
	a.mu.RLock()
	allIDs := make([]string, 0, len(a.nodes))
	for _, n := range a.nodes {
		allIDs = append(allIDs, n.ID)
	}
	a.mu.RUnlock()
	return a.PingNodes(allIDs)
}

// ------------------------- Core & Proxy APIs -------------------------

// GetCoreStatus 界面每秒轮询的状态。
//
// 开关 TUN、切换策略等操作会持有 a.mu 写锁数秒（netsh、路由、内核重启）；这期间
// 轮询不排队等锁，直接返回上一次的状态快照（Busy=true），流量数字仍是实时的
// （独立锁，见 traffic.go）。界面因此不会卡住，操作结束后的下一次轮询即为最新状态。
func (a *App) GetCoreStatus() CoreStatus {
	var st CoreStatus
	if a.mu.TryRLock() {
		st = a.coreStatusLocked()
		a.mu.RUnlock()
		a.statusCache.Store(&st)
	} else if c := a.statusCache.Load(); c != nil {
		st = *c
		st.Busy = true
	} else {
		a.mu.RLock()
		st = a.coreStatusLocked()
		a.mu.RUnlock()
	}
	upSpeed, downSpeed, totalUp, totalDown := a.traffic.snapshot()
	st.UpSpeed = formatSpeed(upSpeed)
	st.DownSpeed = formatSpeed(downSpeed)
	st.TotalUp = formatBytes(totalUp)
	st.TotalDown = formatBytes(totalDown)
	return st
}

// coreStatusLocked 状态中受 a.mu 保护的部分（调用方持有读锁或写锁）。
func (a *App) coreStatusLocked() CoreStatus {
	activeName := "未选择节点"
	activeProto := "无"
	for _, n := range a.nodes {
		if n.Active {
			activeName = n.Name
			activeProto = n.Protocol
			break
		}
	}
	return CoreStatus{
		Running:         a.coreRunning || a.tunRunning,
		CoreType:        a.settings.CoreType,
		CoreVersion:     xrayCoreVersion(),
		SystemProxy:     a.systemProxy,
		RoutingMode:     a.routingMode,
		ActiveNodeName:  activeName,
		ActiveNodeProto: activeProto,
		SocksPort:       a.settings.SocksPort,
		HttpPort:        a.settings.HttpPort,
		TunRunning:      a.tunRunning,
		TunnelMode:      a.tunRunning,
	}
}

func (a *App) ToggleCore(start bool) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if start {
		// 合并架构：TUN 运行时内核是代理大脑，本就不应停 —— 直接确保内核在线即可
		if err := a.startCoreLocked(); err != nil {
			a.coreRunning = false
			a.addLogInternal("error", fmt.Sprintf("Core start failed: %v", err))
			a.savePersisted()
			return false, err
		}
		a.coreRunning = true
		if a.systemProxy {
			setWindowsSystemProxy(true, fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort))
		}
	}
	if !start {
		// 内核是 TUN 的代理大脑：停内核前先软停止 TUN（常驻网卡保留）
		a.stopCoreLocked()
		a.coreRunning = false
		if a.tunRunning {
			a.tunSoftStopLocked()
			a.addLogInternal("warn", "TUN soft-stopped along with core")
		}
		a.traffic.resetSpeed()
		a.addLogInternal("warn", "Core stopped, no longer forwarding traffic")
		if a.systemProxy {
			setWindowsSystemProxy(false, "")
		}
	}
	a.savePersisted()
	return a.coreRunning, nil
}

func (a *App) ToggleSystemProxy(enable bool) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// TUN 接管期间系统代理处于暂停状态：只记下用户的选择，关 TUN 时按它恢复
	if a.tunRunning {
		a.tunPausedSysProxy = enable
		a.addLogInternal("info", fmt.Sprintf("System proxy preference recorded (%v); applied when TUN stops", enable))
		tray.requestRebuild()
		return a.systemProxy, nil
	}
	server := fmt.Sprintf("127.0.0.1:%d", a.settings.HttpPort)
	if err := setWindowsSystemProxy(enable, server); err != nil {
		a.addLogInternal("error", fmt.Sprintf("Failed to set Windows system proxy: %v", err))
		return a.systemProxy, err
	}
	a.systemProxy = enable
	if enable {
		a.addLogInternal("info", fmt.Sprintf("Windows system proxy enabled -> %s", server))
	} else {
		a.addLogInternal("info", "Windows system proxy cleared (direct mode)")
	}
	a.savePersisted()
	tray.requestRebuild()
	return a.systemProxy, nil
}

func (a *App) SetRoutingMode(mode string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 合法策略：内置三种 + SSTap 规则文件（sstap:<rules 文件路径>）
	valid := mode == "bypass-cn" || mode == "global" || mode == "direct" || mode == "proxy-cn" ||
		strings.HasPrefix(mode, "sstap:")
	if !valid {
		mode = "bypass-cn"
	}
	// 四个模式互斥：TUN 运行中选择任一策略 = 关 TUN、回到系统代理模式并应用该策略。
	// 先写策略再软停：软停里重启内核时直接按新策略生成配置，不必再热替换一次。
	if a.tunRunning {
		a.routingMode = mode
		a.tunSoftStopLocked()
		a.addLogInternal("info", fmt.Sprintf("TUN stopped: switched to system-proxy mode (%s)", mode))
		if !a.coreRunning {
			a.savePersisted()
			tray.requestRebuild()
			return false, fmt.Errorf("core is not running after leaving TUN mode")
		}
		a.savePersisted()
		tray.requestRebuild()
		return true, nil
	}

	a.routingMode = mode
	modeLabel := "绕过大陆 (GFWList & CN)"
	switch {
	case mode == "global":
		modeLabel = "全局代理"
	case mode == "direct":
		modeLabel = "全局直连"
	case mode == "proxy-cn":
		modeLabel = "仅代理国内 (China-IP-only)"
	case strings.HasPrefix(mode, "sstap:"):
		modeLabel = "SSTap 规则: " + filepath.Base(strings.TrimPrefix(mode, "sstap:"))
	}
	a.addLogInternal("info", fmt.Sprintf("Routing mode changed to: %s", modeLabel))
	defer tray.requestRebuild()

	if a.coreRunning {
		// 优先就地替换路由规则并切断旧连接（入站不断、keep-alive 连接立即按新策略出站）；
		// 不可用时才整体重启内核。
		err := a.applyRoutingLocked()
		if err != nil && errors.Is(err, errHotSwapUnavailable) {
			a.addLogInternal("warn", fmt.Sprintf("Live routing switch unavailable (%v), restarting core", err))
			err = a.startCoreLocked()
		}
		if err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to restart core after routing change: %v", err))
			a.coreRunning = false
			a.savePersisted()
			return false, err
		}
	}
	a.savePersisted()
	return true, nil
}

// ------------------------- Subscriptions -------------------------

func (a *App) GetSubscriptions() []SubscriptionItem {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]SubscriptionItem, len(a.subscriptions))
	copy(out, a.subscriptions)
	return out
}

// refreshSubscription 真实拉取订阅并解析分享链接，替换该订阅下的所有节点
func (a *App) refreshSubscription(id string) error {
	a.mu.RLock()
	var sub *SubscriptionItem
	for i := range a.subscriptions {
		if a.subscriptions[i].ID == id {
			sub = &a.subscriptions[i]
			break
		}
	}
	if sub == nil {
		a.mu.RUnlock()
		return fmt.Errorf("subscription not found")
	}
	subURL := sub.URL
	subName := sub.Name
	a.mu.RUnlock()

	content, err := fetchSubscriptionContent(subURL)
	if err != nil {
		a.mu.Lock()
		a.addLogInternal("error", fmt.Sprintf("Subscription [%s] fetch failed: %v", subName, err))
		a.mu.Unlock()
		return err
	}

	nodes, skipped := ParseShareLinksReport(content)
	if msg := skippedLinksLog(skipped); msg != "" {
		a.addLogInternal("warn", fmt.Sprintf("Subscription [%s]: %s", subName, msg))
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	for i := range a.subscriptions {
		if a.subscriptions[i].ID == id {
			a.subscriptions[i].NodeCount = len(nodes)
			a.subscriptions[i].UpdatedAt = time.Now().Format("2006-01-02 15:04")
		}
	}
	a.subLastAuto.Store(time.Now().Unix())

	// 检查当前活动节点是否属于该订阅，并记录其特征以便在新列表中保持选择
	activeWasHere := false
	var oldActive NodeItem
	for _, n := range a.nodes {
		if n.Active && n.SubID == id {
			activeWasHere = true
			oldActive = n
			break
		}
	}

	// 替换该订阅下的节点
	var updated []NodeItem
	for _, n := range a.nodes {
		if n.SubID != id {
			updated = append(updated, n)
		}
	}
	// 构建旧节点特征到 ID 的映射，用于在同步时保持节点 ID 稳定
	// （避免前端因 ID 变化误认为节点切换，触发不必要的重新连接）
	oldNodeIDs := make(map[string]string)
	for _, n := range a.nodes {
		if n.SubID == id {
			key := fmt.Sprintf("%s|%d|%s", n.Address, n.Port, n.UUID)
			oldNodeIDs[key] = n.ID
		}
	}
	for i := range nodes {
		// 如果旧节点中有匹配的（地址+端口+UUID），复用旧 ID
		key := fmt.Sprintf("%s|%d|%s", nodes[i].Address, nodes[i].Port, nodes[i].UUID)
		if oldID, ok := oldNodeIDs[key]; ok {
			nodes[i].ID = oldID
		} else {
			nodes[i].ID = fmt.Sprintf("node-%d", time.Now().UnixNano()+int64(i))
		}
		nodes[i].SubID = id
		nodes[i].Group = subName
		updated = append(updated, nodes[i])
	}
	a.nodes = updated

	if activeWasHere {
		a.activeNodeID = ""
		for i := range a.nodes {
			a.nodes[i].Active = false
		}
		// 优先按服务器特征匹配原节点（订阅刷新后节点身份不变时保持选择）
		for i := range a.nodes {
			n := a.nodes[i]
			if n.Address == oldActive.Address && n.Port == oldActive.Port &&
				(oldActive.UUID == "" || n.UUID == oldActive.UUID) {
				a.nodes[i].Active = true
				a.activeNodeID = n.ID
				break
			}
		}
		// 匹配不到则回退第一个节点
		if a.activeNodeID == "" && len(a.nodes) > 0 {
			a.nodes[0].Active = true
			a.activeNodeID = a.nodes[0].ID
		}
		if a.coreRunning && !a.tunRunning {
			if err := a.startCoreLocked(); err != nil {
				a.addLogInternal("error", fmt.Sprintf("Failed to restart core after subscription update: %v", err))
				a.coreRunning = false
			} else {
				a.addLogInternal("info", "Active node replaced by subscription refresh, core restarted")
			}
		}
		// 活动节点被订阅替换 → 走完整切换：活动节点的服务器地址/凭据可能已变，
		// 存量连接必须断开，否则出口 IP 仍停在旧节点上。
		// （TUN 下不先重启内核：热切换出站即可，重启失败会让转发接到死掉的 SOCKS 上。）
		if a.tunRunning {
			var active NodeItem
			foundActive := false
			for _, n := range a.nodes {
				if n.Active {
					active, foundActive = n, true
					break
				}
			}
			if foundActive {
				if err := a.tunHardSwitchLocked(active); err != nil {
					if errors.Is(err, errNodeRejected) {
						a.addLogInternal("error", fmt.Sprintf("Refreshed node rejected in TUN mode, tunnel kept on the previous parameters: %v", err))
					} else {
						a.tunSoftStopLocked()
						a.addLogInternal("error", fmt.Sprintf("Failed to apply subscription update in TUN mode: %v", err))
					}
				}
			}
		} else if a.coreRunning {
			flushDnsClientCache()
		}
	}

	a.addLogInternal("info", fmt.Sprintf("Subscription [%s] updated, %d nodes parsed", subName, len(nodes)))
	a.savePersisted()
	// 订阅更新后后台自动测速全部节点（不阻塞调用方；自动测速协程在本函数释放锁后才读节点）
	a.requestAutoPing()
	return nil
}

func fetchSubscriptionContent(url string) (string, error) {
	client := &http.Client{Timeout: 25 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "KNcloud-WIN/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ------------------------- Logs & Settings -------------------------

func (a *App) GetLogs() []LogItem {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	out := make([]LogItem, len(a.logs))
	copy(out, a.logs)
	return out
}

func (a *App) ClearLogs() {
	a.logMu.Lock()
	a.logs = []LogItem{}
	a.logMu.Unlock()
	a.addLogInternal("info", "Logs cleared by user")
}

func (a *App) GetSettings() AppSettings {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.settings
}

func (a *App) SaveSettings(settings AppSettings) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	old := a.settings
	if settings.SocksPort <= 0 || settings.SocksPort > 65535 {
		settings.SocksPort = old.SocksPort
	}
	if settings.HttpPort <= 0 || settings.HttpPort > 65535 {
		settings.HttpPort = old.HttpPort
	}
	if settings.Theme == "" {
		settings.Theme = old.Theme
	}
	if settings.UiMode != "classic" && settings.UiMode != "simple" {
		settings.UiMode = old.UiMode
		if settings.UiMode == "" {
			settings.UiMode = "classic"
		}
	}
	if a.tunRunning && (old.SocksPort != settings.SocksPort || old.DnsServers != settings.DnsServers) {
		// TUN 转发器连的是 SOCKS 端口、DNS 服务器 /32 防回环按 DNS 设置写入：
		// 运行中改它们会让 TUN 静默断流。拒绝并保持原设置。
		a.addLogInternal("warn", "SOCKS port / DNS servers cannot be changed while TUN is on")
		return fmt.Errorf("TUN 运行中不能修改 SOCKS 端口或 DNS 服务器，请先关闭 TUN")
	}

	a.settings = settings
	a.addLogInternal("info", "Preferences saved")

	// 开机自启：设置项是唯一事实来源，变更时同步写入 / 移除注册表 Run 键；
	// 写注册表失败则回滚设置，避免界面显示与实际自启状态不一致。
	if old.AutoStart != settings.AutoStart {
		if err := setAutoStart(settings.AutoStart); err != nil {
			a.settings.AutoStart = old.AutoStart
			a.addLogInternal("error", fmt.Sprintf("Update auto-start failed: %v", err))
		} else if settings.AutoStart {
			a.addLogInternal("info", "Auto-start on Windows logon enabled")
		} else {
			a.addLogInternal("info", "Auto-start on Windows logon disabled")
		}
	}

	needsRestart := a.coreRunning &&
		(old.SocksPort != settings.SocksPort ||
			old.HttpPort != settings.HttpPort ||
			old.AllowLan != settings.AllowLan ||
			old.MuxEnabled != settings.MuxEnabled ||
			old.DnsServers != settings.DnsServers)

	if needsRestart {
		if err := a.startCoreLocked(); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to restart core with new settings: %v", err))
			a.coreRunning = false
			if a.tunRunning {
				// 内核没起来：TUN 留着就是黑洞，软停回直连
				a.tunSoftStopLocked()
			}
		} else {
			a.addLogInternal("info", "Core restarted with new port/params")
		}
	}
	// 系统代理开着且 HTTP 端口变了，需要刷新注册表
	if a.systemProxy && old.HttpPort != settings.HttpPort {
		setWindowsSystemProxy(true, fmt.Sprintf("127.0.0.1:%d", settings.HttpPort))
	}
	a.savePersisted()
	tray.requestRebuild()
	return nil
}

// ------------------------- Lifecycle -------------------------

// beforeClose 关闭窗口时的拦截点。
// 默认行为是「收进托盘继续后台运行」，只有托盘菜单里的「退出」
// （会先把 quitting 置为 true）才真正退出并清理系统代理 / 内核。
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.RLock()
	quitting := a.quitting
	minimizeToTray := a.settings.MinimizeToTray
	a.mu.RUnlock()

	if !quitting && minimizeToTray && tray.available() {
		a.hideMainWindow()
		a.addLogInternal("info", "Window hidden to tray; use the tray menu to quit")
		return true // 阻止窗口关闭
	}

	a.cleanup()
	return false
}

// cleanup 退出前清理：还原系统代理、停止内核与 TUN、保存配置。
func (a *App) cleanup() {
	a.mu.Lock()
	if a.cleaned {
		a.mu.Unlock()
		return
	}
	a.cleaned = true
	proxyOn := a.systemProxy
	a.systemProxy = false
	// 先释放 a.mu：stopWebLogin 内部会再次获取该锁，RWMutex 不可重入，
	// 持有锁调用会直接死锁（表现为退出时进程卡住）。
	a.mu.Unlock()

	if proxyOn {
		setWindowsSystemProxy(false, "")
	}
	a.stopWebLogin()

	a.mu.Lock()
	a.stopCoreLocked()
	a.coreRunning = false // 软停 TUN 时不要再把内核拉起来
	// tapstack：停转发 + 撤路由；常驻网卡保留在系统里（与 SSTap 的 TAP 一致）
	a.tunSoftStopLocked()
	a.savePersisted()
	a.mu.Unlock()
}

// quitApp 真正退出程序：托盘菜单「退出」与窗口关闭（未开启最小化到托盘）都会走这里。
func (a *App) quitApp() {
	a.mu.Lock()
	if a.quitting {
		a.mu.Unlock()
		return
	}
	a.quitting = true
	ctx := a.ctx
	a.mu.Unlock()

	// 1. 立即隐藏主窗口，给用户即时的视觉反馈与响应
	a.hideMainWindow()

	a.addLogInternal("info", "Exiting KNcloud-WIN, restoring system proxy")

	// 2. 异步卸载托盘图标，避免阻塞主退出流程
	go stopTray()

	// 3. 兜底 watchdog 定时器：如果 Wails runtime.Quit / WebView2 阻塞超过 1.5 秒，强行退出
	go func() {
		time.Sleep(1500 * time.Millisecond)
		// 清理可能卡在系统代理、TUN 或内核停止流程中；watchdog 不得等待清理完成，
		// 否则主窗口虽然关闭，进程仍可能永久残留。
		os.Exit(0)
	}()

	if ctx != nil {
		runtime.Quit(ctx)
		return
	}
	a.cleanup()
	os.Exit(0)
}

// ------------------------- Window Controls -------------------------

// appCtx 读取 Wails 运行时 context。托盘回调可能在 OnStartup 之前触发
// （例如用户立刻又双击了一次图标），所以统一走加锁读取。
func (a *App) appCtx() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ctx
}

// showMainWindow 显示并激活主窗口（托盘左键 / 菜单「显示主界面」）。
func (a *App) showMainWindow() {
	ctx := a.appCtx()
	if ctx == nil {
		return
	}
	runtime.WindowShow(ctx)
	runtime.WindowUnminimise(ctx)
	// 借置顶开关把窗口拉到前台（Wails v2 没有独立的 focus API）
	runtime.WindowSetAlwaysOnTop(ctx, true)
	runtime.WindowSetAlwaysOnTop(ctx, false)
}

// hideMainWindow 隐藏主窗口，程序继续在托盘后台运行。
func (a *App) hideMainWindow() {
	ctx := a.appCtx()
	if ctx == nil {
		return
	}
	runtime.WindowHide(ctx)
}

// focusFromSecondInstance 用户重复启动时唤出已在运行的实例，而不是开第二个进程。
// 第二次启动可能发生在主实例 OnStartup 完成之前，所以先等一下 ctx。
func (a *App) focusFromSecondInstance() {
	for i := 0; i < 60 && a.appCtx() == nil; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	a.showMainWindow()
	a.addLogInternal("info", "Second launch detected, bringing the running instance to front")
}

func (a *App) WindowMin() {
	if ctx := a.appCtx(); ctx != nil {
		runtime.WindowMinimise(ctx)
	}
}

func (a *App) WindowMax() {
	if ctx := a.appCtx(); ctx != nil {
		runtime.WindowToggleMaximise(ctx)
	}
}

func (a *App) WindowClose() {
	if ctx := a.appCtx(); ctx != nil {
		runtime.Quit(ctx)
	}
}

func (a *App) IsWindowMaximized() bool {
	if ctx := a.appCtx(); ctx != nil {
		return runtime.WindowIsMaximised(ctx)
	}
	return false
}
