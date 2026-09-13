package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	xcore "github.com/xtls/xray-core/core"
)

type NodeItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // VMess, VLESS, Trojan, Shadowsocks, Hysteria2
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
}

type SubscriptionItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
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
	// 真正退出需要走托盘菜单的「退出 KNcloud-WIN」。
	MinimizeToTray bool `json:"minimizeToTray"`
}

type App struct {
	ctx            context.Context
	mu             sync.RWMutex
	nodes          []NodeItem
	subscriptions  []SubscriptionItem
	logMu          sync.Mutex // 单独保护 logs / logIDCounter：日志会被托盘、测速等
	logs           []LogItem  // 未持 a.mu 的 goroutine 写入，不能共用 a.mu
	logIDCounter   int64
	settings       AppSettings
	coreRunning    bool
	systemProxy    bool
	routingMode    string
	activeNodeID   string
	totalUpBytes   int64
	totalDownBytes int64
	lastUpSpeed    string
	lastDownSpeed  string
	lastUpSample   int64
	lastDownSample int64
	xrayInst       *xcore.Instance
	tunCmd         *exec.Cmd
	tunRunning     bool
	tunIfaceIdx    uint32
	tunJob         windows.Handle    // sing-box 所在 KILL_ON_JOB_CLOSE Job
	tunProcDone    chan struct{}     // sing-box 进程退出信号
	tunHostRoutes  []mibIPForwardRow // 写入物理网卡的节点 /32 直连路由（断开时回收）
	tunReplacedCore bool             // TUN 启动时是否停掉了正在运行的内核（断开 TUN 时据此恢复常规代理）
	tunSampleUp    int64
	tunSampleDown  int64
	account        AccountInfo
	quitting       bool // true 表示用户已确认退出（托盘菜单「退出」），关闭窗口不再拦截
	webLogin       *webLoginManager // 网页授权登录的本地回调服务（见 weblogin.go）；用指针避免拷贝内部互斥锁
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
		lastUpSpeed:   "0 B/s",
		lastDownSpeed: "0 B/s",
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

	// 系统托盘：右下角常驻图标 + 右键菜单
	startTray(a)

	// 真实内核流量统计轮询：每秒采样一次计数器
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				up, down, ok := a.tunTrafficSample()
				if !ok {
					up, down, ok = a.coreTrafficSample()
				}
				a.mu.Lock()
				if ok {
					du := up - a.lastUpSample
					dd := down - a.lastDownSample
					if du < 0 {
						du = up
					}
					if dd < 0 {
						dd = down
					}
					a.lastUpSample = up
					a.lastDownSample = down
					a.totalUpBytes += du
					a.totalDownBytes += dd
					a.lastUpSpeed = formatSpeed(du)
					a.lastDownSpeed = formatSpeed(dd)
				} else {
					a.lastUpSpeed = "0 B/s"
					a.lastDownSpeed = "0 B/s"
				}
				a.mu.Unlock()
			}
		}
	}()

	// 登录过官网账户：启动时自动同步订阅节点
	go func() {
		time.Sleep(2 * time.Second)
		a.mu.RLock()
		loggedIn := a.account.LoggedIn
		subID := a.account.SubID
		a.mu.RUnlock()
		if loggedIn && subID != "" {
			_ = a.refreshSubscription(subID)
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

	var selected NodeItem
	found := false
	for i := range a.nodes {
		if a.nodes[i].ID == id {
			a.nodes[i].Active = true
			selected = a.nodes[i]
			found = true
			a.activeNodeID = id
		} else {
			a.nodes[i].Active = false
		}
	}
	if !found {
		return selected, fmt.Errorf("node not found")
	}

	a.addLogInternal("info", fmt.Sprintf("Primary route switched to node: [%s] %s (%s:%d)", selected.Protocol, selected.Name, selected.Address, selected.Port))
	if a.tunRunning {
		if err := a.startTunLocked(false); err != nil {
			a.tunRunning = false
			a.addLogInternal("error", fmt.Sprintf("Failed to restart TUN after node switch: %v", err))
		}
	}
	if a.coreRunning {
		if err := a.startCoreLocked(); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to restart core after node switch: %v", err))
			a.coreRunning = false
			a.savePersisted()
			return selected, err
		}
	}
	a.savePersisted()
	return selected, nil
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
	nodes := ParseShareLinks(links)
	if len(nodes) == 0 {
		return 0, fmt.Errorf("no valid share links found (supported: vmess/vless/trojan/ss/hysteria2)")
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

	// 编辑的是当前活动节点且内核运行中 → 用新参数重启
	if old.Active && a.coreRunning {
		if err := a.startCoreLocked(); err != nil {
			a.coreRunning = false
			a.addLogInternal("error", fmt.Sprintf("Failed to restart core after node edit: %v", err))
		}
	}
	// 编辑的是当前活动节点且 TUN 运行中 → 用新参数重启 TUN（否则旧进程仍按原节点/原配置转发）
	if old.Active && a.tunRunning {
		if err := a.startTunLocked(false); err != nil {
			a.tunRunning = false
			a.addLogInternal("error", fmt.Sprintf("Failed to restart TUN after node edit: %v", err))
		}
	}
	a.savePersisted()
	tray.requestRebuild()
	return nil
}

func (a *App) DeleteNode(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	wasActive := false
	var updated []NodeItem
	for _, n := range a.nodes {
		if n.ID == id {
			wasActive = n.Active
			continue
		}
		updated = append(updated, n)
	}
	a.nodes = updated

	if wasActive {
		a.activeNodeID = ""
		if len(a.nodes) > 0 {
			a.nodes[0].Active = true
			a.activeNodeID = a.nodes[0].ID
		}
		if a.coreRunning {
			a.stopCoreLocked()
			a.coreRunning = false
			a.addLogInternal("warn", "Active node deleted, core stopped; select a node and start again")
		}
		// TUN 还挂在被删节点上：有其它节点则切到新选中的节点继续跑，没有就停掉
		if a.tunRunning {
			if len(a.nodes) > 0 {
				if err := a.startTunLocked(false); err != nil {
					a.tunRunning = false
					a.addLogInternal("error", fmt.Sprintf("Failed to restart TUN after active node deletion: %v", err))
				}
			} else {
				a.stopTunLocked()
				a.addLogInternal("warn", "Active node deleted and no nodes left, TUN stopped")
			}
		}
	}
	a.addLogInternal("warn", fmt.Sprintf("Node removed (ID: %s)", id))
	a.savePersisted()
	tray.requestRebuild()
	return nil
}

func (a *App) PingNode(id string) int {
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
	a.mu.RUnlock()

	if !found {
		return -2
	}

	// 真连接测速：经该节点完整代理链路请求测速 URL
	latency := testNodeRealDelay(target)

	a.mu.Lock()
	for i := range a.nodes {
		if a.nodes[i].ID == id {
			a.nodes[i].Delay = latency
			break
		}
	}
	a.mu.Unlock()

	if latency == -2 {
		a.addLogInternal("warn", fmt.Sprintf("Real-connection test failed for node [%s] (timeout or unreachable)", target.Name))
	} else {
		a.addLogInternal("info", fmt.Sprintf("Real-connection test for node [%s]: %d ms", target.Name, latency))
	}
	return latency
}

func (a *App) PingAllNodes() []NodeItem {
	a.mu.RLock()
	nodesCopy := make([]NodeItem, len(a.nodes))
	copy(nodesCopy, a.nodes)
	a.mu.RUnlock()

	// 并发真连接测速，最多同时 5 个临时实例
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, node := range nodesCopy {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			a.PingNode(id)
		}(node.ID)
	}
	wg.Wait()

	a.addLogInternal("info", "Real-connection latency test completed for all nodes")
	return a.GetNodes()
}

// ------------------------- Core & Proxy APIs -------------------------

func (a *App) GetCoreStatus() CoreStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

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
		UpSpeed:         a.lastUpSpeed,
		DownSpeed:       a.lastDownSpeed,
		TotalUp:         formatBytes(a.totalUpBytes),
		TotalDown:       formatBytes(a.totalDownBytes),
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
		// TUN 全局模式与内核模式互斥
		if a.tunRunning {
			a.stopTunLocked()
		}
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
	} else {
		a.stopCoreLocked()
		a.coreRunning = false
		a.lastUpSpeed = "0 B/s"
		a.lastDownSpeed = "0 B/s"
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

func (a *App) SetRoutingMode(mode string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if mode != "bypass-cn" && mode != "global" && mode != "direct" {
		mode = "bypass-cn"
	}
	a.routingMode = mode
	modeLabel := "绕过大陆 (GFWList & CN)"
	if mode == "global" {
		modeLabel = "全局代理"
	} else if mode == "direct" {
		modeLabel = "全局直连"
	}
	a.addLogInternal("info", fmt.Sprintf("Routing mode changed to: %s", modeLabel))
	if a.coreRunning {
		if err := a.startCoreLocked(); err != nil {
			a.addLogInternal("error", fmt.Sprintf("Failed to restart core after routing change: %v", err))
			a.coreRunning = false
		}
	}
	a.savePersisted()
	return true
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

	nodes := ParseShareLinks(content)
	a.mu.Lock()
	defer a.mu.Unlock()

	for i := range a.subscriptions {
		if a.subscriptions[i].ID == id {
			a.subscriptions[i].NodeCount = len(nodes)
			a.subscriptions[i].UpdatedAt = time.Now().Format("2006-01-02 15:04")
		}
	}

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
	for i := range nodes {
		nodes[i].ID = fmt.Sprintf("node-%d", time.Now().UnixNano()+int64(i))
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
		if a.coreRunning {
			if err := a.startCoreLocked(); err != nil {
				a.addLogInternal("error", fmt.Sprintf("Failed to restart core after subscription update: %v", err))
				a.coreRunning = false
			} else {
				a.addLogInternal("info", "Active node replaced by subscription refresh, core restarted")
			}
		}
		// TUN 运行中且活动节点被替换 → 用新节点参数重启 TUN
		if a.tunRunning {
			if err := a.startTunLocked(false); err != nil {
				a.tunRunning = false
				a.addLogInternal("error", fmt.Sprintf("Failed to restart TUN after subscription update: %v", err))
			}
		}
	}

	a.addLogInternal("info", fmt.Sprintf("Subscription [%s] updated, %d nodes parsed", subName, len(nodes)))
	a.savePersisted()
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
// 默认行为是「收进托盘继续后台运行」，只有托盘菜单里的「退出 KNcloud-WIN」
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
	defer a.mu.Unlock()

	if a.systemProxy {
		setWindowsSystemProxy(false, "")
		a.systemProxy = false
	}
	a.stopWebLogin()
	a.stopCoreLocked()
	a.stopTunLocked()
	a.savePersisted()
}

// quitApp 真正退出程序：托盘菜单「退出 KNcloud-WIN」与窗口关闭（未开启最小化到托盘）都会走这里。
func (a *App) quitApp() {
	a.mu.Lock()
	if a.quitting {
		a.mu.Unlock()
		return
	}
	a.quitting = true
	ctx := a.ctx
	a.mu.Unlock()

	a.addLogInternal("info", "Exiting KNcloud-WIN, restoring system proxy")

	// 先收掉托盘图标，再让 Wails 走正常退出流程（会触发 beforeClose -> cleanup）
	stopTray()

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
