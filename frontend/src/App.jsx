import kncFgBlack from './assets/knc-fg-black.png';
import kncFgWhite from './assets/knc-fg-white.png';
import kncLoginDark from './assets/knc-login-dark.png';
import kncLoginLight from './assets/knc-login-light.png';
import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Activity,
  Server,
  GitFork,
  BookOpen,
  Terminal,
  Settings,
  Menu,
  Sun,
  Moon,
  Minus,
  Square,
  X,
  Play,
  Pause,
  RefreshCw,
  Plus,
  Trash2,
  Zap,
  Globe,
  ArrowUpRight,
  ArrowDownLeft,
  CheckCircle2,
  Sliders,
  Search,
  Check,
  Copy,
  Pencil,
  Power,
  ChevronDown,
  LayoutGrid,
  SlidersHorizontal,
  FolderInput,
  LoaderCircle,
  Gauge,
  LogOut,
  CircleHelp,
} from 'lucide-react';

import {
  GetNodes,
  SelectNode,
  AddNode,
  DeleteNode,
  DeleteNodes,
  PingNode,
  PingAllNodes,
  PingNodes,
  StartAutoPing,
  IsAutoPinging,
  GetCoreStatus,
  RestartCore,
  GetAppVersion,
  CheckForUpdate,
  StartUpdate,
  GetUpdateProgress,
  SetRoutingMode,
  SimpleConnect,
  GetSubscriptions,
  UpdateNode,
  ImportNodesFromLinks,
  CopyNodeShareLink,
  ImportNodesFromClipboard,
  Login,
  GetAccount,
  RefreshAccount,
  Logout,
  SyncNodes,
  StartWebLogin,
  GetLogs,
  ClearLogs,
  GetSettings,
  SaveSettings,
  WindowMin,
  WindowMax,
  WindowClose
} from '../wailsjs/go/main/App';
import { EventsOn, WindowSetSize, WindowUnmaximise, BrowserOpenURL } from '../wailsjs/runtime';

const protoLabel = (n) => (n.protocol === 'HTTP' && n.security === 'tls') ? 'HTTPS' : n.protocol;

export default function App() {
  // 简易模式内容少，窗口切到紧凑尺寸；普通模式恢复默认大小
  // （全局最小尺寸在 main.go 里放开了到 380x560，这里的目标值在其之上）
  const WINDOW_SIZE = { simple: { w: 420, h: 640 }, classic: { w: 1120, h: 760 } };
  const applyWindowSize = async (mode) => {
    const s = WINDOW_SIZE[mode] || WINDOW_SIZE.classic;
    // 窗口处于最大化时 SetSize 不生效，会一直停在大尺寸；先还原成普通窗口
    try { await WindowUnmaximise(); } catch (e) { /* 未最大化时忽略 */ }
    WindowSetSize(s.w, s.h);
  };

  // 节点延迟的展示文字与配色（简易模式节点下拉用）
  const delayText = d => d > 0 ? `${d}ms` : d === -2 ? '超时' : '未测';
  const delayColor = d => d > 0
    ? (d < 300 ? '#3fbf6f' : d < 800 ? '#e5a50a' : '#ff6b6b')
    : d === -2 ? '#ff6b6b' : 'var(--text-tertiary)';

  const [theme, setTheme] = useState('dark');
  const brandLogo = theme === 'dark' ? kncLoginDark : kncLoginLight;
  const loginLogo = theme === 'dark' ? kncLoginDark : kncLoginLight;
  const [uiMode, setUiMode] = useState('simple'); // classic=普通模式, simple=简易模式（登录后默认简洁）
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  
  // App core states
  const [status, setStatus] = useState({
    running: true,
    coreType: 'Xray-core',
    coreVersion: 'v1.8.24',
    systemProxy: false,
    routingMode: 'bypass-cn',
    upSpeed: '0 B/s',
    downSpeed: '0 B/s',
    totalUp: '0 GB',
    totalDown: '0 GB',
    activeNodeName: '未选择节点',
    activeNodeProto: 'VLESS'
  });

  const [nodes, setNodes] = useState([]);
  // 简易模式连接检测结果：idle=未连接, checking=检测中, ok=节点可用, fail=节点无效, none=未选择节点
  const [simpleNet, setSimpleNet] = useState('idle');
  
  // 简易模式自定义节点下拉是否展开
  const [nodeMenuOpen, setNodeMenuOpen] = useState(false);
  const [nodeMenuStyle, setNodeMenuStyle] = useState({});
  // 首次从后端取到数据前显示启动页，避免按默认 uiMode 闪出空的简易模式界面
  const [booted, setBooted] = useState(false);
  const nodeTriggerRef = useRef(null);
  // 下拉收起后让触发按钮失焦：否则切出窗口再切回时 WebView2 会对仍持有焦点的按钮显示焦点环
  useEffect(() => {
    if (!nodeMenuOpen && nodeTriggerRef.current) nodeTriggerRef.current.blur();
  }, [nodeMenuOpen]);
  const [selectedProto, setSelectedProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [deleteConfirmIds, setDeleteConfirmIds] = useState(null); // 待确认删除的节点 id 列表
  const [dragBox, setDragBox] = useState(null); // 框选矩形（视口坐标）
  const dragRef = useRef(null);
  const suppressClickRef = useRef(false);
  const nodeListRef = useRef(null);
  const [selectedNodeIds, setSelectedNodeIds] = useState([]); // 节点列表多选（Ctrl+A / Ctrl+点击 / Shift+点击）
  const [switchingNodeId, setSwitchingNodeId] = useState(null); // 正在切换中的节点 ID
  const [isPingingAll, setIsPingingAll] = useState(false);
  // 后台自动测速（启动 / 订阅更新后 / 仪表盘刷新按钮）是否进行中，由后端 kncloud:auto-ping 事件驱动
  const [autoTesting, setAutoTesting] = useState(false);
  // 仪表盘节点网格的显示顺序（节点 ID）。测速进行中保持不动，一轮结束后再按延迟重排，避免方块边测边跳
  const [quickPickOrder, setQuickPickOrder] = useState([]);

  // Subscriptions & Logs
  const [subscriptions, setSubscriptions] = useState([]);
  const [logs, setLogs] = useState([]);
  const [settings, setLocalSettings] = useState({
    socksPort: 10808,
    httpPort: 10809,
    autoStart: true,
    allowLan: false,
    muxEnabled: true,
    coreType: 'Xray-core',
    dnsServers: '1.1.1.1, 8.8.8.8, 223.5.5.5',
    minimizeToTray: true,
    subUpdateHours: 0
  });

  // Modals
  const [showAddNodeModal, setShowAddNodeModal] = useState(false);
  const [editingNodeId, setEditingNodeId] = useState(null);
  const [newNode, setNewNode] = useState({
    name: '',
    protocol: 'VLESS',
    address: '',
    port: 443,
    uuid: '',
    security: 'reality',
    network: 'tcp',
    group: 'Custom'
  });

  const [showImportModal, setShowImportModal] = useState(false);
  const [importText, setImportText] = useState('');

  // 账户
  const [account, setAccount] = useState(null); // null = 尚未从后端加载
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [loginErr, setLoginErr] = useState('');
  const [loginBusy, setLoginBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [webLoginWaiting, setWebLoginWaiting] = useState(false); // 网页授权登录等待中
  // 仪表盘四个模式按钮（绕过大陆 / 全局代理 / 全局直连 / TUN 模式，四选一）：
  // pendingMode 是点击后的乐观高亮，后端完成（开关 TUN 可能要数秒）后清空、回落到真实状态
  const [pendingMode, setPendingMode] = useState(null);
  const modeBusyRef = useRef(false);

  const fmtGB = (b) => {
    if (!b || b <= 0) return '0 GB';
    if (b >= 1024 ** 3) return (b / 1024 ** 3).toFixed(2) + ' GB';
    return (b / 1024 ** 2).toFixed(0) + ' MB';
  };

  // 应用内 Toast 通知（替代原生 alert）
  const [toasts, setToasts] = useState([]);
  const toastIdRef = useRef(0);
  const showToast = (msg, type = 'info') => {
    const id = ++toastIdRef.current;
    setToasts(list => [...list, { id, msg, type }]);
    setTimeout(() => {
      setToasts(list => list.filter(t => t.id !== id));
    }, 3500);
  };
  const renderToasts = () => (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`}>{t.msg}</div>
      ))}
    </div>
  );

  // Load initial data
  useEffect(() => {
    refreshAllData();
    const interval = setInterval(() => {
      fetchStatusAndLogs();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // 托盘菜单里的操作（切模式、切节点、开关系统代理等）会通知界面同步刷新
  useEffect(() => {
    const off = EventsOn('kncloud:refresh', () => {
      refreshAllData();
    });
    // 托盘等后端操作的结果提示
    const offToast = EventsOn('kncloud:toast', (t) => {
      if (t && t.msg) showToast(t.msg, t.type || 'info');
    });
    return () => {
      if (typeof off === 'function') off();
      if (typeof offToast === 'function') offToast();
    };
  }, []);

  // 测速结果逐个推送：边测边更新延迟；后台自动测速开始/结束只改卡片头部的小指示，不弹提示
  useEffect(() => {
    const offDelay = EventsOn('kncloud:node-delay', (ev) => {
      if (!ev || !ev.id) return;
      setNodes(prev => prev.map(n => (n.id === ev.id ? { ...n, delay: ev.delay } : n)));
    });
    const offAuto = EventsOn('kncloud:auto-ping', async (ev) => {
      const running = !!(ev && ev.running);
      setAutoTesting(running);
      if (!running) {
        try { setNodes(await GetNodes()); } catch (e) { /* ignore */ }
      }
    });
    // 界面加载晚于后台测速开始时，补查一次进行中状态
    IsAutoPinging().then(r => setAutoTesting(!!r)).catch(() => {});
    return () => {
      if (typeof offDelay === 'function') offDelay();
      if (typeof offAuto === 'function') offAuto();
    };
  }, []);

  const handleRetestAll = async () => {
    if (autoTesting || isPingingAll) return;
    setAutoTesting(true); // 乐观显示；结束由 kncloud:auto-ping 事件复位
    try {
      await StartAutoPing();
    } catch (e) {
      setAutoTesting(false);
    }
  };

  // 内核状态（仪表盘状态条与「重启内核」按钮）
  const coreState = status.coreState || (status.running ? 'running' : 'stopped');
  const coreBad = coreState !== 'running';
  const coreStateLabel = {
    running: '内核运行中',
    stopped: '内核已停止',
    retrying: '内核启动失败 · 自动重试中…',
    failed: '内核启动失败' + (status.corePortError ? '：端口被占用' : ''),
  }[coreState] || '内核已停止';

  // 关闭按钮的语义取决于「关闭窗口时最小化到托盘」开关
  const closeWindowTitle = settings.minimizeToTray
    ? '关闭（最小化到系统托盘）'
    : '关闭并退出程序';

  const refreshAllData = async () => {
    try {
      const [curStatus, curNodes, curSubs, curLogs, curSettings, curAccount] = await Promise.all([
        GetCoreStatus(),
        GetNodes(),
        GetSubscriptions(),
        GetLogs(),
        GetSettings(),
        GetAccount()
      ]);
      if (curStatus) setStatus(curStatus);
      if (curNodes) setNodes(curNodes);
      if (curSubs) setSubscriptions(curSubs);
      if (curLogs) setLogs(curLogs);
      if (curAccount) setAccount(curAccount);
      if (curSettings) {
        setLocalSettings(curSettings);
        if (curSettings.theme === 'light') setTheme('light');
        else if (curSettings.theme === 'dark') setTheme('dark');
        // 按持久化的模式 + 登录态统一决定窗口尺寸：
        //   未登录 → 登录页紧凑尺寸；已登录 → 简洁模式紧凑尺寸 / 普通模式默认尺寸
        // （此前只在 uiMode==='simple' 时调整，classic 持久化的简单模式下窗口不会缩小）
        if (curSettings.uiMode === 'simple') setUiMode('simple');
        else if (curSettings.uiMode === 'classic') setUiMode('classic');
        const loggedIn = !!(curAccount && curAccount.loggedIn);
        applyWindowSize(loggedIn
          ? (curSettings.uiMode === 'classic' ? 'classic' : 'simple')
          : 'simple');
      }
      setBooted(true);
    } catch (e) {
      console.error("Init data load error", e);
      setBooted(true);
    }
  };

  const fetchStatusAndLogs = async () => {
    try {
      const curStatus = await GetCoreStatus();
      if (curStatus) setStatus(curStatus);
      const curLogs = await GetLogs();
      if (curLogs) setLogs(curLogs);
    } catch (e) {
      // ignore
    }
  };

  // Actions
  // 「重启内核」：停止并重新启动内核，后端按当前模式重新应用系统代理（TUN 下保持暂停）
  const [restartingCore, setRestartingCore] = useState(false);
  const handleRestartCore = async () => {
    if (restartingCore) return;
    setRestartingCore(true);
    try {
      await RestartCore();
      showToast('内核已重新启动', 'success');
    } catch (e) {
      showToast('重启内核失败：' + (e?.message || e), 'error');
    } finally {
      try { setStatus(await GetCoreStatus()); } catch (_) {}
      setRestartingCore(false);
    }
  };

  const handleThemeToggle = async () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    try {
      await SaveSettings({ ...settings, theme: next });
      setLocalSettings(prev => ({ ...prev, theme: next }));
    } catch (e) {
      // 主题切换失败不影响使用
    }
  };

  const handleUiModeToggle = async () => {
    const next = uiMode === 'classic' ? 'simple' : 'classic';
    setUiMode(next);
    applyWindowSize(next);
    try {
      await SaveSettings({ ...settings, uiMode: next });
      setLocalSettings(prev => ({ ...prev, uiMode: next }));
    } catch (e) {
      // 模式切换失败不影响使用
    }
  };

  // 简易模式：一键切换分流策略（内核与系统代理由程序启动逻辑自动开启，按钮不再启停 TUN）
  //   点击连接 = 绕过大陆（海外走代理、大陆直连）；点击断开 = 全局直连
  const handleSimpleConnect = async () => {
    // TUN 运行中也算「已连接」：断开 = 关 TUN 并切到全局直连
    const connected = status.tunnelMode || status.routingMode === 'bypass-cn';
    const next = connected ? 'direct' : 'bypass-cn';
    // 连接动作一发出就进入「正在连接…」，检测结果由下面的自动检测更新
    setSimpleNet(next === 'bypass-cn' ? 'checking' : 'idle');
    try {
      await SetRoutingMode(next);
    } catch (e) {
      showToast(String(e?.message || e).replace(/^.*?: /, ''), 'error');
    }
    setStatus(await GetCoreStatus());
  };

  const handleLogin = async () => {
    if (loginBusy) return;
    setLoginErr('');
    setLoginBusy(true);
    try {
      const res = await Login(loginForm.email, loginForm.password);
      setAccount(res);
      setLoginForm({ email: '', password: '' });
      setSubscriptions(await GetSubscriptions());
      setNodes(await GetNodes());
      // 登录成功默认进入简洁模式（窗口同步切到紧凑尺寸），并持久化，
      // 否则下次启动 settings 里仍是 classic，窗口不会缩小
      setUiMode('simple');
      applyWindowSize('simple');
      try {
        const s = await GetSettings();
        await SaveSettings({ ...s, uiMode: 'simple' });
        setLocalSettings(prev => ({ ...prev, uiMode: 'simple' }));
      } catch (e) { /* ignore */ }
    } catch (e) {
      setLoginErr(String(e?.message || e).replace(/^.*?: /, ''));
    }
    setLoginBusy(false);
  };

  // 网页授权登录：后端拉起浏览器并在本机等回调，结果通过事件异步回传
  useEffect(() => {
    const offOk = EventsOn('kncloud:web-login', async (acct) => {
      setWebLoginWaiting(false);
      if (acct) setAccount(acct);
      try {
        setSubscriptions(await GetSubscriptions());
        setNodes(await GetNodes());
      } catch (e) { /* ignore */ }
      // 登录成功默认进入简洁模式（窗口同步切到紧凑尺寸），并持久化
      setUiMode('simple');
      applyWindowSize('simple');
      try {
        const s = await GetSettings();
        await SaveSettings({ ...s, uiMode: 'simple' });
        setLocalSettings(prev => ({ ...prev, uiMode: 'simple' }));
      } catch (e) { /* ignore */ }
      showToast('网页登录成功，订阅已同步', 'success');
    });
    const offErr = EventsOn('kncloud:web-login-error', (msg) => {
      setWebLoginWaiting(false);
      showToast(String(msg || '网页登录失败'), 'error');
    });
    return () => {
      if (typeof offOk === 'function') offOk();
      if (typeof offErr === 'function') offErr();
    };
  }, []);

  const handleWebLogin = async () => {
    if (webLoginWaiting) return;
    setLoginErr('');
    try {
      await StartWebLogin();
      setWebLoginWaiting(true);
    } catch (e) {
      setLoginErr(String(e?.message || e).replace(/^.*?: /, ''));
    }
  };

  const handleLogout = async () => {
    try {
      setAccount(await Logout());
    } catch (e) { /* ignore */ }
  };

  const handleUpdateSubscription = async () => {
    if (syncing) return;
    setSyncing(true);
    try {
      // 1. 刷新官网套餐、流量及最新订阅地址
      const res = await RefreshAccount();
      setAccount(res);
      // 2. 同步最新的服务器节点列表
      await SyncNodes();
      setSubscriptions(await GetSubscriptions());
      setNodes(await GetNodes());
      showToast('订阅及节点已更新', 'success');
    } catch (e) {
      showToast('更新失败：' + (e?.message || e), 'error');
    } finally {
      setSyncing(false);
    }
  };

  const handleSimpleSelectNode = async (id) => {
    if (!id) return;
    const target = nodes.find(n => n.id === id);
    try {
      await SelectNode(id);
      if (target && status.tunnelMode) {
        showToast(`已切换至「${target.name}」，已断开旧连接，请刷新页面查看新 IP`, 'success');
      }
    } catch (e) {
      const msg = String(e?.message || e);
      if (msg.includes('superseded')) return; // 被更新的点击取代，由那次请求刷新界面
      showToast('切换节点失败：' + msg, 'error');
    }
    setNodes(await GetNodes());
    setStatus(await GetCoreStatus());
  };

  // 简易模式节点可用性自动检测：PingNode 在后端起临时内核，经该节点真实请求
  // 探测 URL，结果（delay > 0 可用 / -2 失败）同时回写到节点列表的延迟显示
  const checkSimpleNode = async () => {
    const cur = nodes.find(n => n.active);
    if (!cur) {
      // 没有节点不属于「连接失败」，用独立的 none 状态显示「未选择节点」
      setSimpleNet('none');
      return;
    }
    setSimpleNet('checking');
    try {
      await PingNode(cur.id);
      const updated = await GetNodes();
      setNodes(updated);
      const n = updated.find(x => x.id === cur.id);
      setSimpleNet(n && n.delay > 0 ? 'ok' : 'fail');
    } catch (e) {
      setSimpleNet('fail');
    }
  };

  // 代理开启时自动检测当前节点；切换节点 / 断开后重新检测或复位
  const simpleActiveId = nodes.find(n => n.active)?.id;
  useEffect(() => {
    if (uiMode !== 'simple') return;
    if (!status.tunnelMode && (status.routingMode || 'bypass-cn') === 'direct') {
      setSimpleNet('idle');
      return;
    }
    checkSimpleNode();
  }, [uiMode, status.routingMode, status.tunnelMode, simpleActiveId]);

  // 四个模式互斥：TUN = 虚拟网卡全局接管；其余三个是系统代理模式下的分流策略。
  // TUN 运行中点其它三个之一，后端先关 TUN 再按所点策略回到系统代理模式。
  // 点击即乐观高亮（滑块立刻移动），后端耗时操作不阻塞界面；完成后以真实状态为准。
  const handleModeSelect = async (mode) => {
    const current = status.tunnelMode ? 'tun' : (status.routingMode || 'bypass-cn');
    if (modeBusyRef.current || mode === current) return;
    modeBusyRef.current = true;
    setPendingMode(mode);
    const enteringTun = mode === 'tun';
    const leavingTun = status.tunnelMode && !enteringTun;
    if (enteringTun || leavingTun) showToast(enteringTun ? '正在启动 TUN…' : '正在关闭 TUN…', 'info');
    let ok = false;
    try {
      if (enteringTun) await SimpleConnect(true);
      else await SetRoutingMode(mode);
      ok = true;
    } catch (e) {
      const msg = String(e?.message || e).replace(/^.*?: /, '');
      showToast(enteringTun ? msg : '切换模式失败：' + msg, 'error');
    } finally {
      try {
        const s = await GetCoreStatus();
        setStatus(s);
        if (ok && (enteringTun || leavingTun)) showToast(s.tunnelMode ? 'TUN 已开启' : 'TUN 已关闭', 'success');
      } catch (_) {}
      setPendingMode(null);
      modeBusyRef.current = false;
    }
  };

  // 路由页「全局路由模式」卡片与仪表盘按钮共用同一套互斥逻辑
  const handleRoutingChange = (mode) => handleModeSelect(mode);

  // 换节点：
  //  - 「已连接」只按后端确认的状态判断；切换进行中的乐观高亮不算，点别的节点会发起新切换；
  //  - 新点击会取代仍在进行的旧请求（后端让排队中的旧请求直接放弃），只有最后一次点击的结果生效；
  //  - 前端兜底 20 秒超时（后端自己 12 秒就会报超时），界面绝不会一直停在「切换中…」。
  const switchSeqRef = useRef(0);
  const handleSelectNode = async (id) => {
    const target = nodes.find(n => n.id === id);
    if (!target) return;
    if (switchingNodeId === id) {
      showToast(`正在切换至「${target.name}」…`, 'info');
      return;
    }
    if (!switchingNodeId && target.active) {
      showToast(`当前已连接至「${target.name}」`, 'info');
      return;
    }

    const seq = ++switchSeqRef.current;
    setSwitchingNodeId(id);
    // 乐观更新：立刻让选中圆点与高亮跳到目标节点，界面零延迟即时响应
    setNodes(prev => prev.map(n => ({ ...n, active: n.id === id })));
    setStatus(prev => ({
      ...prev,
      activeNodeName: target.name,
      activeNodeProto: target.protocol
    }));

    let timer;
    try {
      await Promise.race([
        SelectNode(id),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('切换超时，请稍后重试')), 20000);
        })
      ]);
      if (seq !== switchSeqRef.current) return; // 已被更新的点击取代
      // TUN 模式下换节点会强制断开存量连接（否则旧节点的 keep-alive 连接
      // 会让出口 IP 看起来没变），提醒用户刷新页面而不是以为切换失败。
      showToast(
        status.tunnelMode
          ? `已切换至「${target.name}」，已断开旧连接，请刷新页面查看新 IP`
          : `已切换至「${target.name}」`,
        'success'
      );
    } catch (e) {
      if (seq !== switchSeqRef.current) return;
      const msg = String(e?.message || e);
      if (msg.includes('superseded')) return;
      showToast('切换节点失败：' + msg, 'error');
    } finally {
      clearTimeout(timer);
      if (seq === switchSeqRef.current) {
        // 先收起「切换中…」，再刷新列表：后端若仍被长操作占着锁，刷新可能要等，
        // 不能让标记跟着一起挂住（此前就是在这里一直转）。刷新本身也限时 5 秒。
        setSwitchingNodeId(null);
        try {
          const [updatedNodes, updatedStatus] = await Promise.race([
            Promise.all([GetNodes(), GetCoreStatus()]),
            new Promise((_, reject) => setTimeout(() => reject(new Error('refresh timeout')), 5000))
          ]);
          if (seq === switchSeqRef.current) {
            if (updatedNodes) setNodes(updatedNodes);
            if (updatedStatus) setStatus(updatedStatus);
          }
        } catch (_) { /* 下一次定时轮询会补上 */ }
      }
    }
  };

  const handlePingSingleNode = async (id, e) => {
    e.stopPropagation();
    await PingNode(id);
    const updatedNodes = await GetNodes();
    setNodes(updatedNodes);
  };

  // Ctrl+R：真连接测速（多选时批量测速所有选中节点；单选或未选时测速当前节点）
  const pingingActiveRef = useRef(false);
  const handlePingSelected = async () => {
    if (pingingActiveRef.current || isPingingAll) return;

    if (selectedNodeIds.length > 1) {
      pingingActiveRef.current = true;
      setIsPingingAll(true);
      showToast(`正在对选中的 ${selectedNodeIds.length} 个节点进行真连接测速…`, "info");
      try {
        const res = await PingNodes(selectedNodeIds);
        setNodes(res);
        showToast(`已完成 ${selectedNodeIds.length} 个节点的批量测速`, "success");
      } catch (err) {
        showToast("批量测速失败：" + (err?.message || err), "error");
      } finally {
        setIsPingingAll(false);
        pingingActiveRef.current = false;
      }
      return;
    }

    let targetNode = null;
    if (selectedNodeIds.length === 1) {
      targetNode = nodes.find(n => n.id === selectedNodeIds[0]);
    }
    if (!targetNode) {
      targetNode = nodes.find(n => n.active);
    }
    if (!targetNode) {
      showToast("未选择节点，无法测速", "error");
      return;
    }

    pingingActiveRef.current = true;
    showToast(`正在真连接测速「${targetNode.name}」…`);
    try {
      await PingNode(targetNode.id);
      const updated = await GetNodes();
      setNodes(updated);
      const n = updated.find(x => x.id === targetNode.id);
      if (n && n.delay > 0) {
        showToast(`「${n.name}」测速完成：${n.delay} ms`, "success");
      } else {
        showToast(`「${targetNode.name}」测速超时或失败`, "error");
      }
    } catch (e) {
      showToast("测速失败：" + (e?.message || e), "error");
    } finally {
      pingingActiveRef.current = false;
    }
  };

  useEffect(() => {
    const onKey = async (e) => {
      // Ctrl+R 测速
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "r" || e.key === "R")) {
        e.preventDefault(); // 拦截 WebView 默认的 Ctrl+R 刷新页面
        handlePingSelected();
        return;
      }
      // Esc 取消节点多选
      if (e.key === "Escape" && deleteConfirmIds) {
        e.preventDefault();
        setDeleteConfirmIds(null);
        return;
      }
      if (e.key === "Escape" && selectedNodeIds.length > 0) {
        e.preventDefault();
        setSelectedNodeIds([]);
        return;
      }
      // Delete 删除选中节点（先弹确认）
      if (e.key === "Delete" && !e.ctrlKey && !e.metaKey && !e.altKey && activeTab === "servers"
          && selectedNodeIds.length > 0 && !deleteConfirmIds && !showAddNodeModal && !showImportModal) {
        const t = e.target;
        const tag = ((t && t.tagName) || "").toLowerCase();
        if (tag !== "input" && tag !== "textarea" && tag !== "select" && !(t && t.isContentEditable)) {
          e.preventDefault();
          setDeleteConfirmIds([...selectedNodeIds]);
          return;
        }
      }
      // 删除确认框：Enter 确认
      if (deleteConfirmIds && e.key === "Enter") {
        e.preventDefault();
        confirmDeleteNodes();
        return;
      }
      // Enter：节点列表选中单个节点时启用它
      if (e.key === "Enter" && !e.ctrlKey && !e.metaKey && !e.altKey && !e.shiftKey && activeTab === "servers"
          && selectedNodeIds.length === 1 && !showAddNodeModal && !showImportModal && !switchingNodeId) {
        const t = e.target;
        const tag = ((t && t.tagName) || "").toLowerCase();
        if (tag !== "input" && tag !== "textarea" && tag !== "select" && tag !== "button" && !(t && t.isContentEditable)) {
          e.preventDefault();
          const target = nodes.find(n => n.id === selectedNodeIds[0]);
          if (target && !target.active) handleSelectNode(target.id);
          return;
        }
      }
      // Ctrl+A 节点列表全选
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "a" || e.key === "A")) {
        if (activeTab === "servers") {
          const t = e.target;
          const tag = ((t && t.tagName) || "").toLowerCase();
          if (tag !== "input" && tag !== "textarea" && tag !== "select" && !(t && t.isContentEditable)) {
            e.preventDefault();
            const allIds = filteredNodes.map(n => n.id);
            setSelectedNodeIds(allIds);
            showToast(`已全选 ${allIds.length} 个节点（按 Ctrl+R 批量测速）`, "info");
            return;
          }
        }
      }
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      if (activeTab !== "servers") return;
      const key = (e.key || "").toLowerCase();
      if (key !== "c" && key !== "v") return;
      const t = e.target;
      const tag = ((t && t.tagName) || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || (t && t.isContentEditable)) return;
      e.preventDefault();
      if (key === "c") {
        const cur = nodes.find(n => n.active);
        if (!cur) {
          showToast("未选择节点，无法复制", "error");
          return;
        }
        try {
          await CopyNodeShareLink(cur.id);
          showToast(`已复制「${cur.name}」的分享链接到剪贴板`, "success");
        } catch (err) {
          showToast("复制失败：" + (err?.message || err), "error");
        }
      } else {
        try {
          const count = await ImportNodesFromClipboard();
          if (count > 0) {
            setNodes(await GetNodes());
            showToast(`已从剪贴板导入 ${count} 个节点`, "success");
          }
        } catch (err) {
          showToast("导入失败：" + (err?.message || err), "error");
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const handlePingAll = async () => {
    if (isPingingAll) return;
    setIsPingingAll(true);
    try {
      const res = await PingAllNodes();
      if (res) setNodes(res);
    } catch (err) {
      showToast('测速失败：' + (err?.message || err), 'error');
    } finally {
      setIsPingingAll(false);
    }
  };

  const handleDeleteNode = async (id, e) => {
    e.stopPropagation();
    await DeleteNode(id);
    const updatedNodes = await GetNodes();
    setNodes(updatedNodes);
  };

  const confirmDeleteNodes = async () => {
    const ids = deleteConfirmIds;
    setDeleteConfirmIds(null);
    if (!ids || ids.length === 0) return;
    try {
      await DeleteNodes(ids);
      setNodes(await GetNodes());
      setSelectedNodeIds([]);
      showToast(`已删除 ${ids.length} 个节点`, "success");
    } catch (err) {
      showToast("删除失败：" + (err?.message || err), "error");
    }
  };

  // 鼠标拖动框选：在节点列表上按住左键拖动，矩形覆盖到的节点即被选中；
  // 按住 Ctrl 拖动则在原有选择上追加。
  const handleListMouseDown = (e) => {
    if (e.button !== 0) return;
    if (e.target.closest('button, input, textarea, select, a')) return;
    const scroller = nodeListRef.current && nodeListRef.current.closest('.content-surface');
    if (!scroller) return;
    const sr = scroller.getBoundingClientRect();
    dragRef.current = {
      scroller,
      // 起点用“滚动内容坐标”记录，滚动时框选仍然对得上
      sx: e.clientX - sr.left + scroller.scrollLeft,
      sy: e.clientY - sr.top + scroller.scrollTop,
      cx: e.clientX,
      cy: e.clientY,
      base: (e.ctrlKey || e.metaKey) ? [...selectedNodeIds] : [],
      active: false,
      timer: null,
    };
    const update = () => {
      const d = dragRef.current;
      if (!d) return;
      const r = d.scroller.getBoundingClientRect();
      const x0 = d.sx - d.scroller.scrollLeft + r.left;
      const y0 = d.sy - d.scroller.scrollTop + r.top;
      const left = Math.min(x0, d.cx), right = Math.max(x0, d.cx);
      const top = Math.min(y0, d.cy), bottom = Math.max(y0, d.cy);
      if (!d.active && right - left < 5 && bottom - top < 5) return;
      d.active = true;
      setDragBox({ left, top, width: right - left, height: bottom - top });
      const hit = [];
      nodeListRef.current.querySelectorAll('[data-node-id]').forEach(el => {
        const b = el.getBoundingClientRect();
        if (b.right >= left && b.left <= right && b.bottom >= top && b.top <= bottom) {
          hit.push(el.getAttribute('data-node-id'));
        }
      });
      setSelectedNodeIds(Array.from(new Set([...d.base, ...hit])));
    };
    const onMove = (ev) => {
      const d = dragRef.current;
      if (!d) return;
      d.cx = ev.clientX;
      d.cy = ev.clientY;
      update();
      if (d.active) ev.preventDefault();
      // 靠近上下边缘时自动滚动
      const r = d.scroller.getBoundingClientRect();
      const edge = 40;
      let dy = 0;
      if (ev.clientY < r.top + edge) dy = -12;
      else if (ev.clientY > r.bottom - edge) dy = 12;
      if (d.timer) { clearInterval(d.timer); d.timer = null; }
      if (dy && d.active) {
        d.timer = setInterval(() => { d.scroller.scrollTop += dy; update(); }, 16);
      }
    };
    const onUp = () => {
      const d = dragRef.current;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      if (d && d.timer) clearInterval(d.timer);
      if (d && d.active) {
        suppressClickRef.current = true; // 拖完松手不要触发卡片点击（单选）
        setTimeout(() => { suppressClickRef.current = false; }, 0);
      }
      dragRef.current = null;
      setDragBox(null);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const resetNodeForm = () => {
    setEditingNodeId(null);
    setNewNode({
      name: '',
      protocol: 'VLESS',
      address: '',
      port: 443,
      uuid: '',
      security: 'reality',
      network: 'tcp',
      group: 'Custom'
    });
  };

  const openEditNode = (node, e) => {
    e.stopPropagation();
    setEditingNodeId(node.id);
    setNewNode({
      name: node.name || '',
      protocol: node.protocol || 'VLESS',
      address: node.address || '',
      port: node.port || 443,
      uuid: node.uuid || '',
      security: node.security || 'none',
      network: node.network || 'tcp',
      group: node.group || 'Custom'
    });
    setShowAddNodeModal(true);
  };

  const handleCreateNode = async () => {
    if (!newNode.address) return;
    try {
      if (editingNodeId) {
        await UpdateNode({ ...newNode, id: editingNodeId, port: parseInt(newNode.port, 10) || 443 });
      } else {
        await AddNode({ ...newNode, port: parseInt(newNode.port, 10) || 443 });
      }
    } catch (e) {
      showToast('保存节点失败：' + (e?.message || e), 'error');
    }
    setShowAddNodeModal(false);
    resetNodeForm();
    const updatedNodes = await GetNodes();
    setNodes(updatedNodes);
  };



  const handleImportLinks = async () => {
    if (!importText.trim()) return;
    try {
      const count = await ImportNodesFromLinks(importText);
      setShowImportModal(false);
      setImportText('');
      setNodes(await GetNodes());
      setActiveTab('servers');
      showToast('成功导入 ' + count + ' 个节点！', 'success');
    } catch (e) {
      showToast('导入失败：' + (e?.message || e), 'error');
    }
  };

  // ---------- 手动在线更新（首选项设置 →「关于与更新」）：不自动检查、不弹窗 ----------
  const [appVersion, setAppVersion] = useState('');
  const [updInfo, setUpdInfo] = useState(null);
  const [updChecking, setUpdChecking] = useState(false);
  const [updProgress, setUpdProgress] = useState({ stage: 'idle', percent: 0, message: '' });
  useEffect(() => {
    GetAppVersion().then(v => setAppVersion(v || 'dev')).catch(() => {});
    GetUpdateProgress().then(p => p && setUpdProgress(p)).catch(() => {});
    const off = EventsOn('kncloud:update-progress', (p) => {
      if (!p) return;
      if (p.stage === 'error') {
        // 下载 / 校验 / 安装失败：错误走 Toast，进度区复位
        showToast(p.message || '更新失败', 'error');
        setUpdProgress({ stage: 'idle', percent: 0, message: '' });
        return;
      }
      setUpdProgress(p);
    });
    return () => { if (typeof off === 'function') off(); };
  }, []);
  const updBusy = ['downloading', 'verifying', 'extracting', 'installing', 'restarting'].includes(updProgress.stage);
  const handleCheckUpdate = async () => {
    if (updChecking || updBusy) return;
    setUpdChecking(true);
    try {
      const info = await CheckForUpdate();
      if (updProgress.stage === 'error') setUpdProgress({ stage: 'idle', percent: 0, message: '' });
      if (info?.hasUpdate) {
        // 有新版本：保留卡片内的版本说明与「立即更新」按钮
        setUpdInfo(info);
      } else {
        // 已是最新 / 开发版 / 缺安装包：一次性结果走 Toast
        setUpdInfo(null);
        const latest = info?.latestVersion && info.message === '已是最新版本' ? `（${info.latestVersion}）` : '';
        showToast((info?.message || '已是最新版本') + latest, info?.message === '已是最新版本' ? 'success' : 'info');
      }
    } catch (e) {
      setUpdInfo(null);
      showToast('检查更新失败：' + String(e?.message || e), 'error');
    } finally {
      setUpdChecking(false);
    }
  };
  const handleStartUpdate = async () => {
    if (updBusy) return;
    try {
      setUpdProgress({ stage: 'downloading', percent: 0, message: '准备下载…' });
      await StartUpdate();
    } catch (e) {
      setUpdProgress({ stage: 'idle', percent: 0, message: '' });
      showToast('更新失败：' + String(e?.message || e), 'error');
    }
  };

  const handleSaveSettings = async () => {
    await SaveSettings(settings);
    showToast('首选项已成功保存！', 'success');
  };

  // Filtered nodes
  const filteredNodes = nodes;

  // 仪表盘节点网格：全部节点按真连接延迟排序（已测速升序 → 超时 → 未测速垫底，同档保持原顺序）。
  // 当前节点原位高亮，不置顶：点击切换时方块不移动。
  const delayRank = (d) => (d > 0 ? 0 : d === -2 ? 1 : 2);
  const sortByDelay = (list) => list
    .map((n, i) => ({ n, i }))
    .sort((x, y) => {
      const rx = delayRank(x.n.delay), ry = delayRank(y.n.delay);
      if (rx !== ry) return rx - ry;
      if (rx === 0 && x.n.delay !== y.n.delay) return x.n.delay - y.n.delay;
      return x.i - y.i;
    })
    .map(x => x.n);
  const pingInProgress = autoTesting || isPingingAll;
  const nodeIdsKey = nodes.map(n => n.id).join('|');
  useEffect(() => {
    setQuickPickOrder(prev => {
      if (pingInProgress && prev.length) {
        // 测速中：保持现有顺序，只剔除已删除的、把新增的接到末尾
        const ids = new Set(nodes.map(n => n.id));
        const kept = prev.filter(id => ids.has(id));
        const keptSet = new Set(kept);
        return [...kept, ...nodes.filter(n => !keptSet.has(n.id)).map(n => n.id)];
      }
      return sortByDelay(nodes).map(n => n.id);
    });
    // 只在节点集合变化、或一轮测速开始/结束时重排；单个延迟更新不触发
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeIdsKey, pingInProgress]);
  const quickPickNodes = (() => {
    const byId = new Map(nodes.map(n => [n.id, n]));
    const ordered = quickPickOrder.map(id => byId.get(id)).filter(Boolean);
    // 顺序尚未同步到最新节点集合的那一帧：补上缺失的节点
    if (ordered.length !== nodes.length) {
      const seen = new Set(ordered.map(n => n.id));
      nodes.forEach(n => { if (!seen.has(n.id)) ordered.push(n); });
    }
    return ordered;
  })();
  const tileDelayClass = (d) => d > 0 ? (d < 300 ? 'qp-delay-good' : d < 800 ? 'qp-delay-medium' : 'qp-delay-bad') : d === -2 ? 'qp-delay-bad' : 'qp-delay-none';
  const tileDelayText = (d) => d > 0 ? `${d} ms` : d === -2 ? '超时' : '未测';
  // 节点卡片：从名称拆出地区代码与 IPv6 标记（Windows 不渲染国旗 emoji，用地区代码徽标代替）
  const REGION_CODES = [
    ['香港', 'HK'], ['台湾', 'TW'], ['澳门', 'MO'], ['日本', 'JP'], ['韩国', 'KR'], ['新加坡', 'SG'],
    ['美国', 'US'], ['英国', 'UK'], ['德国', 'DE'], ['法国', 'FR'], ['荷兰', 'NL'], ['加拿大', 'CA'],
    ['澳大利亚', 'AU'], ['俄罗斯', 'RU'], ['印度', 'IN'], ['马来西亚', 'MY'], ['泰国', 'TH'],
    ['越南', 'VN'], ['菲律宾', 'PH'], ['土耳其', 'TR'], ['巴西', 'BR'], ['阿根廷', 'AR'], ['中国', 'CN'],
  ];
  const tileRegion = (name = '') => {
    for (const [k, c] of REGION_CODES) if (name.includes(k)) return c;
    const m = name.match(/\b([A-Z]{2})\b/);
    return m ? m[1] : (name.trim()[0] || '?');
  };
  const tileSplitName = (name = '') => {
    const v6 = /[\[(（【]\s*v6\s*[\])）】]|ipv6/i.test(name);
    const clean = name.replace(/\s*[\[(（【]\s*v6\s*[\])）】]\s*/ig, ' ').trim() || name;
    return { clean, v6 };
  };
  const tileBars = (d) => d > 0 ? (d < 150 ? 4 : d < 300 ? 3 : d < 600 ? 2 : 1) : 0;

  // 四选一的当前模式：点击后立即显示目标（乐观），否则按真实状态（TUN 优先于分流策略）
  const MODE_ORDER = ['bypass-cn', 'global', 'direct', 'tun'];
  const actualMode = status.tunnelMode ? 'tun' : (status.routingMode || 'bypass-cn');
  const shownMode = pendingMode || actualMode;
  const modeIndex = Math.max(0, MODE_ORDER.indexOf(shownMode));
  const MODE_INFO = {
    'bypass-cn': { title: '绕过大陆', desc: '系统代理 · 国内网站直连，其余经节点转发' },
    global: { title: '全局代理', desc: '系统代理 · 全部流量经节点转发（局域网除外）' },
    direct: { title: '全局直连', desc: '系统代理 · 全部直连，不经过节点' },
    tun: { title: 'TUN 全局接管', desc: '虚拟网卡接管整机流量，全部经节点转发（局域网除外）' },
  };
  const heroInfo = MODE_INFO[actualMode] || { title: '自定义规则', desc: '系统代理 · 按 SSTap 规则文件分流' };

  // 登录页与简洁模式同尺寸（420x640）；登录成功后由模式切换逻辑控制窗口
  useEffect(() => {
    if (account && !account.loggedIn) applyWindowSize('simple');
  }, [account && account.loggedIn]);

  // ---------------- 启动页（内核启动期间后端暂时忙，数据未就绪） ----------------
  if (!booted) {
    return (
      <div className={`app-window ${theme === 'dark' ? 'dark-theme' : ''}`}>
        <header className="titlebar drag-region">
          <div className="titlebar-left">
            <img src={brandLogo} alt="KNcloud" style={{ height: "22px", width: "auto", display: "block" }} />
          </div>
          <div className="titlebar-right no-drag">
            <button className="win-caption-btn" onClick={() => WindowMin()} title="最小化"><Minus size={13} /></button>
            <button className="win-caption-btn btn-close" onClick={() => WindowClose()} title="关闭"><X size={14} /></button>
          </div>
        </header>
        <div className="boot-body">
          <LoaderCircle size={28} className="spin" />
          <span>正在启动…</span>
        </div>
      </div>
    );
  }

  // ---------------- 登录页（未登录且未跳过时显示） ----------------
  if (account && !account.loggedIn) {
    return (
      <div className={`app-window ${theme === 'dark' ? 'dark-theme' : ''}`}>
        <header className="titlebar drag-region">
          <div className="titlebar-left" />
          <div className="titlebar-right no-drag">
            <button className="win-caption-btn" onClick={() => WindowMin()} title="最小化"><Minus size={13} /></button>
            <button className="win-caption-btn" onClick={() => WindowMax()} title="最大化"><Square size={11} /></button>
            <button className="win-caption-btn btn-close" onClick={() => WindowClose()} title="关闭"><X size={14} /></button>
          </div>
        </header>
        {renderToasts()}
        <div className="login-body">
          <img src={loginLogo} alt="" className="login-logo" style={{ height: "64px", width: "auto", objectFit: "contain" }} />
          <input
            type="email"
            className="win11-input login-input"
            placeholder="邮箱地址"
            value={loginForm.email}
            onChange={e => setLoginForm({ ...loginForm, email: e.target.value })}
          />
          <input
            type="password"
            className="win11-input login-input"
            placeholder="密码"
            value={loginForm.password}
            onChange={e => setLoginForm({ ...loginForm, password: e.target.value })}
            onKeyDown={e => { if (e.key === 'Enter') handleLogin(); }}
          />
          {loginErr && <div className="login-err">{loginErr}</div>}
          <button className="win11-btn primary login-btn" disabled={loginBusy || webLoginWaiting} onClick={handleLogin}>
            {loginBusy ? '登录中…' : '登 录'}
          </button>
          <div className="login-divider"><span>或</span></div>
          <button className="win11-btn login-btn" disabled={loginBusy || webLoginWaiting} onClick={handleWebLogin}>
            <Globe size={14} />
            <span>{webLoginWaiting ? '等待网页授权…' : '通过网站登录'}</span>
          </button>
        </div>
      </div>
    );
  }

  // 简易模式节点下拉：按窗口剩余空间限高，下方放不下时向上展开，保证能滚到最后一个节点
  const toggleNodeMenu = () => {
    if (nodeMenuOpen) { setNodeMenuOpen(false); return; }
    const r = nodeTriggerRef.current?.getBoundingClientRect();
    if (r) {
      const margin = 12;
      const below = window.innerHeight - r.bottom - 6 - margin;
      const above = r.top - 6 - margin - 40; // 40 = 标题栏
      if (below < 200 && above > below) {
        setNodeMenuStyle({ top: 'auto', bottom: 'calc(100% + 6px)', maxHeight: Math.max(120, Math.min(360, above)) });
      } else {
        setNodeMenuStyle({ maxHeight: Math.max(120, Math.min(360, below)) });
      }
    }
    setNodeMenuOpen(true);
  };

  // ---------------- 简易模式（点击即用，无复杂设置） ----------------
  if (uiMode === 'simple') {
    const activeNode = nodes.find(n => n.active);
    // 简易模式：绕过大陆或 TUN（普通模式里开启的）都算已连接
    const routing = status.routingMode || 'bypass-cn';
    const simpleOn = status.tunnelMode || routing === 'bypass-cn';
    return (
      <div className={`app-window ${theme === 'dark' ? 'dark-theme' : ''}`}>
        <header className="titlebar drag-region">
          <div className="titlebar-left">
            <img src={brandLogo} alt="KNcloud-WIN" style={{ height: "22px", width: "auto", display: "block" }} />
          </div>
          <div className="titlebar-right no-drag">
            <button className="theme-toggle-btn" onClick={handleUiModeToggle} title="切换到普通模式（完整设置）">
              <SlidersHorizontal size={15} />
            </button>
            <button className="theme-toggle-btn" onClick={handleThemeToggle} title="切换浅色 / 深色主题">
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button className="win-caption-btn" onClick={() => WindowMin()} title="最小化">
              <Minus size={13} />
            </button>
            <button className="win-caption-btn" onClick={() => WindowMax()} title="最大化">
              <Square size={11} />
            </button>
            <button className="win-caption-btn btn-close" onClick={() => WindowClose()} title={closeWindowTitle}>
              <X size={14} />
            </button>
          </div>
        </header>

        {renderToasts()}
        <div className="simple-body">
          <button
            className={[
              'simple-power-btn',
              simpleOn && simpleNet === 'ok' ? 'connected' : '',
              simpleOn && simpleNet === 'checking' ? 'connecting' : '',
              simpleOn && simpleNet === 'fail' ? 'failed' : '',
            ].filter(Boolean).join(' ')}
            onClick={handleSimpleConnect}
            title={simpleOn ? '点击切换到全局直连' : '点击开启分流代理（绕过大陆）'}
          >
            {simpleOn && simpleNet === 'checking'
              ? <LoaderCircle size={56} className="spin" />
              : <Power size={56} />}
          </button>

          <div
            className={`simple-status-text ${simpleOn && simpleNet === 'checking' ? 'checking' : ''}`}
            style={simpleNet === 'fail' ? { color: '#ff6b6b' } : (simpleOn && simpleNet === 'ok' ? { color: '#3fbf6f' } : null)}
          >
            {!simpleOn
              ? '开始连接'
              : simpleNet === 'checking'
                ? '正在连接…'
                : simpleNet === 'fail'
                  ? '连接失败，请更换节点'
                  : simpleNet === 'none'
                    ? '未选择节点'
                    : '链接成功'}
          </div>

          <div className="simple-speed">
            <span>↑ {status.upSpeed}</span>
            <span>↓ {status.downSpeed}</span>
          </div>

          <div className="simple-node-area" style={{ position: 'relative' }}>
            <label>代理节点</label>
            <button type="button" ref={nodeTriggerRef} className="simple-node-trigger" onClick={toggleNodeMenu}>
              {activeNode ? (
                <>
                  <span className={`proto-badge proto-${activeNode.protocol.toLowerCase()}`}>{protoLabel(activeNode)}</span>
                  <span className="simple-node-name">{activeNode.name}</span>
                  <span className="simple-node-delay" style={{ color: delayColor(activeNode.delay) }}>
                    {delayText(activeNode.delay)}
                  </span>
                </>
              ) : (
                <span className="simple-node-name">暂无节点，请在普通模式中添加</span>
              )}
              <ChevronDown
                size={14}
                style={{ flexShrink: 0, opacity: 0.6, transition: 'transform .15s', transform: nodeMenuOpen ? 'rotate(180deg)' : 'none' }}
              />
            </button>

            {nodeMenuOpen && (
              <>
                <div style={{ position: 'fixed', inset: 0, zIndex: 90 }} onClick={() => setNodeMenuOpen(false)} />
                <div className="simple-node-menu" style={nodeMenuStyle}>
                  {nodes.length === 0 && <div className="simple-node-empty">暂无节点，请在普通模式中添加</div>}
                  {nodes.map(n => (
                    <div
                      key={n.id}
                      className={`simple-node-item ${activeNode && n.id === activeNode.id ? 'active' : ''}`}
                      onClick={() => {
                        setNodeMenuOpen(false);
                        if (!activeNode || n.id !== activeNode.id) handleSimpleSelectNode(n.id);
                      }}
                    >
                      <span className={`proto-badge proto-${n.protocol.toLowerCase()}`}>{protoLabel(n)}</span>
                      <span className="simple-node-name">{n.name}</span>
                      <span className="simple-node-delay" style={{ color: delayColor(n.delay) }}>
                        {delayText(n.delay)}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          {account && account.loggedIn && (
            <div className="simple-account">
              <div className="simple-account-row">
                <span>{account.email}</span>
                <span>{account.planName || 'KNcloud 套餐'}</span>
              </div>
              <div className="simple-account-bar">
                <div style={{
                  width: account.transferEnable > 0
                    ? Math.min(100, Math.round((account.usedUp + account.usedDown) * 100 / account.transferEnable)) + '%'
                    : '0%'
                }} />
              </div>
              <div className="simple-account-row small">
                <span>已用 {fmtGB(account.usedUp + account.usedDown)} / {account.transferEnable > 0 ? fmtGB(account.transferEnable) : '无限'}</span>
                <span>{account.expire}</span>
              </div>
              <div className="simple-account-actions">
                <button className="win11-btn" onClick={handleUpdateSubscription} disabled={syncing}>
                  <RefreshCw size={13} className={syncing ? 'spin' : ''} />
                  <span>{syncing ? '更新中…' : '更新订阅'}</span>
                </button>
                <button className="win11-btn" onClick={handlePingAll} disabled={isPingingAll}>
                  <Gauge size={13} />
                  <span>{isPingingAll ? '测速中…' : '测试节点'}</span>
                </button>
                <button className="win11-btn danger" onClick={handleLogout}>
                  <span>退出登录</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 实时上传/下载（只统计走节点的流量），并入订阅卡右侧
  const speedStats = (
    <div className="speed-stats" title="仅统计经代理节点的流量">
      <div className="speed-stat up">
        <ArrowUpRight size={14} />
        <div>
          <div className="speed-val">{status.upSpeed}</div>
          <div className="speed-total">本地累计 {status.totalUp}</div>
        </div>
      </div>
      <div className="speed-stat down">
        <ArrowDownLeft size={14} />
        <div>
          <div className="speed-val">{status.downSpeed}</div>
          <div className="speed-total">本地累计 {status.totalDown}</div>
        </div>
      </div>
    </div>
  );

  return (
    <div className={`app-window ${theme === 'dark' ? 'dark-theme' : ''}`}>
      {renderToasts()}
      {/* Windows 11 TitleBar */}
      <header className="titlebar drag-region">
        <div className="titlebar-left">
          <img src={brandLogo} alt="KNcloud-WIN" style={{ height: "22px", width: "auto", display: "block" }} />
        </div>



        <div className="titlebar-right no-drag">
          <button className="theme-toggle-btn" onClick={handleUiModeToggle} title="切换到简易模式（点击即用）">
            <LayoutGrid size={15} />
          </button>
          <button
            className="theme-toggle-btn"
            onClick={handleThemeToggle}
            title="切换浅色 / 深色主题"
          >
            {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
          </button>
          <button className="win-caption-btn" onClick={() => WindowMin()} title="最小化">
            <Minus size={13} />
          </button>
          <button className="win-caption-btn" onClick={() => WindowMax()} title="最大化">
            <Square size={11} />
          </button>
          <button className="win-caption-btn btn-close" onClick={() => WindowClose()} title={closeWindowTitle}>
            <X size={14} />
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="app-body">
        {/* Left Windows 11 Navigation Bar */}
        <nav className={`nav-sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
          <div className="nav-top-actions">
            <button
              className="hamburger-btn"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              title="展开 / 折叠侧边栏"
            >
              <Menu size={16} />
            </button>

            <div className="nav-items-list">
              <button
                className={`nav-item-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
                onClick={() => setActiveTab('dashboard')}
              >
                <Activity size={17} />
                {!sidebarCollapsed && <span>仪表盘</span>}
              </button>
              <button
                className={`nav-item-btn ${activeTab === 'servers' ? 'active' : ''}`}
                onClick={() => setActiveTab('servers')}
              >
                <Server size={17} />
                {!sidebarCollapsed && <span>节点列表</span>}
              </button>
              <button
                className={`nav-item-btn ${activeTab === 'routing' ? 'active' : ''}`}
                onClick={() => setActiveTab('routing')}
              >
                <GitFork size={17} />
                {!sidebarCollapsed && <span>路由分流</span>}
              </button>

              <button
                className={`nav-item-btn ${activeTab === 'logs' ? 'active' : ''}`}
                onClick={() => setActiveTab('logs')}
              >
                <Terminal size={17} />
                {!sidebarCollapsed && <span>实时日志</span>}
              </button>
            </div>
          </div>

          <div className="nav-footer-area">
            <button
              className={`nav-item-btn ${activeTab === 'settings' ? 'active' : ''}`}
              onClick={() => setActiveTab('settings')}
            >
              <Settings size={17} />
              {!sidebarCollapsed && <span>首选项设置</span>}
            </button>
          </div>
        </nav>

        {/* Right Main Content */}
        <main className="content-surface">
          {/* TAB 1: DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="content-header">
                <div>
                  <h1 className="content-title">运行状态概览</h1>
                </div>
                <div className={`core-status core-${coreState}`}>
                  <span className="core-dot" aria-hidden="true" />
                  <span className="core-label" title={status.coreError || ''}>{coreStateLabel}</span>
                  <button
                    type="button"
                    className={`win11-btn core-restart-btn ${coreBad ? 'primary' : ''}`}
                    onClick={handleRestartCore}
                    disabled={restartingCore}
                    title="停止并重新启动 Xray 内核，按当前模式重新应用系统代理"
                  >
                    <RefreshCw size={13} className={restartingCore ? 'spin' : ''} />
                    {restartingCore ? '重启中…' : '重启内核'}
                  </button>
                </div>
              </div>

              {(coreState === 'failed' || coreState === 'retrying') && (
                <div className="win11-card core-error-card" role="alert">
                  <div className="core-error-title">
                    {coreState === 'retrying' ? '内核启动失败，正在自动重试…' : '内核启动失败'}
                  </div>
                  {status.coreError && <div className="core-error-reason">{status.coreError}</div>}
                  <div className="core-error-hint">
                    {status.corePortError ? (
                      <>
                        端口被其它程序占用。请在
                        <button type="button" className="core-link" onClick={() => setActiveTab('settings')}>首选项设置</button>
                        中更换 SOCKS / HTTP 端口，保存后内核会自动重新启动。
                      </>
                    ) : coreState === 'retrying'
                      ? '程序会按 2 秒 / 5 秒 / 15 秒的间隔自动重试，也可以立即点击「重启内核」。'
                      : '自动重试已结束。排查原因后点击「重启内核」再试一次。系统代理已暂时关闭，避免断网。'}
                  </div>
                </div>
              )}

              {account && account.loggedIn && (
                <div className="acct-split">
                  <div className="win11-card account-card acct-left">
                    <div className="acct-head">
                    <div className="acct-id">
                      <span className="acct-email">{account.email}</span>
                      <span className="acct-plan">{account.planName || 'KNcloud 会员'}</span>
                    </div>
                    <div className="acct-actions">
                      <button
                        type="button"
                        className="acct-action acct-icon-btn"
                        onClick={() => BrowserOpenURL((account.domain || 'https://www.kncloud.top').replace(/\/+$/, '') + '/')}
                        title={`打开官网（${(account.domain || 'https://www.kncloud.top').replace(/^https?:\/\//, '').replace(/\/+$/, '')}）`}
                        aria-label="打开官网"
                      >
                        <Globe size={15} />
                      </button>
                      <button
                        type="button"
                        className="acct-action acct-icon-btn"
                        onClick={handleUpdateSubscription}
                        disabled={syncing}
                        title={syncing ? '更新中…' : `更新订阅${subscriptions[0] ? '（上次同步 ' + subscriptions[0].updatedAt + '）' : ''}`}
                        aria-label="更新订阅"
                      >
                        <RefreshCw size={15} className={syncing ? 'spin' : ''} />
                      </button>
                      <button
                        type="button"
                        className="acct-action acct-icon-btn acct-logout-text"
                        onClick={handleLogout}
                        title="退出登录"
                        aria-label="退出登录"
                      >
                        <LogOut size={15} />
                      </button>
                    </div>
                    </div>
                    <div className="acct-usage">
                      <div className="acct-value">
                        {fmtGB(account.usedUp + account.usedDown)}
                        <span className="acct-sub"> / {account.transferEnable > 0 ? fmtGB(account.transferEnable) : '无限'} · {account.expire}</span>
                      </div>
                      <div className="simple-account-bar acct-bar">
                        <div style={{
                          width: account.transferEnable > 0
                            ? Math.min(100, Math.max(1, Math.round((account.usedUp + account.usedDown) * 100 / account.transferEnable))) + '%'
                            : '0%'
                        }} />
                      </div>
                    </div>
                  </div>
                  <div className="win11-card acct-stat" title="仅统计经代理节点的流量">
                    <div className="acct-label"><span>实时上传</span><ArrowUpRight size={16} color="#0078d4" /></div>
                    <div className="acct-speed">{status.upSpeed}</div>
                    <div className="acct-sub">本地累计上行: {status.totalUp}</div>
                  </div>
                  <div className="win11-card acct-stat" title="仅统计经代理节点的流量">
                    <div className="acct-label"><span>实时下载</span><ArrowDownLeft size={16} color="#107c41" /></div>
                    <div className="acct-speed">{status.downSpeed}</div>
                    <div className="acct-sub">本地累计下行: {status.totalDown}</div>
                  </div>
                </div>
              )}


              {/* 代理模式：四个互斥按钮占满整行（状态由高亮按钮本身表达，不再单独展示） */}
              <div className="win11-card mode-card">
                  <div
                    className={`segmented-control mode-switch mode-switch-full ${pendingMode ? 'busy' : ''}`}
                    role="radiogroup"
                    aria-busy={!!pendingMode}
                  >
                    <span
                      className="segment-indicator"
                      aria-hidden="true"
                      style={{ transform: `translateX(calc(${modeIndex} * (100% + 4px)))` }}
                    />
                    {[
                      { id: 'bypass-cn', label: '绕过大陆' },
                      { id: 'global', label: '全局代理' },
                      { id: 'direct', label: '全局直连' },
                      { id: 'tun', label: 'TUN 模式', title: '虚拟网卡全局接管整机流量（需管理员权限）' },
                    ].map(m => (
                      <button
                        key={m.id}
                        type="button"
                        role="radio"
                        aria-checked={shownMode === m.id}
                        className={`segment-btn ${shownMode === m.id ? 'active' : ''}`}
                        onClick={() => handleModeSelect(m.id)}
                        title={m.title}
                      >
                        {m.label}
                      </button>
                    ))}
                  </div>
              </div>

              {/* 未登录时没有订阅卡，实时速率单独成一张小卡 */}
              {!(account && account.loggedIn) && (
                <div className="win11-card speed-card-solo">{speedStats}</div>
              )}

              {/* Quick Node Switcher in Dashboard：全部节点紧凑网格，点击即切换 */}
              <div className="win11-card">
                <div className="qp-header">
                  <div className="qp-title">
                    <h3>推荐节点快速选择</h3>
                    {pingInProgress ? (
                      <span className="qp-testing"><LoaderCircle size={12} className="spin" />测速中…</span>
                    ) : (
                      <span className="qp-hint">按延迟排序 · 点击切换</span>
                    )}
                  </div>
                  <div className="qp-actions">
                    <button
                      className="win11-btn qp-icon-btn"
                      onClick={handleRetestAll}
                      disabled={pingInProgress || nodes.length === 0}
                      title="重新测速全部节点"
                    >
                      <RefreshCw size={13} className={pingInProgress ? 'spin' : ''} />
                    </button>
                  </div>
                </div>
                {nodes.length === 0 ? (
                  <div className="qp-empty">暂无节点，请先更新订阅或导入节点</div>
                ) : (
                  <div className="qp-grid">
                    {quickPickNodes.map(node => (
                      <button
                        key={node.id}
                        type="button"
                        className={`qp-tile${node.active ? ' active' : ''}${switchingNodeId === node.id ? ' switching' : ''}`}
                        onClick={() => handleSelectNode(node.id)}
                        title={`${node.name}\n${node.protocol} · ${node.address}:${node.port}`}
                      >
                        {(() => {
                          const { clean, v6 } = tileSplitName(node.name);
                          const bars = tileBars(node.delay);
                          return (
                            <>
                              <span className="qp-top">
                                <span className="qp-region">{tileRegion(node.name)}</span>
                                <span className="qp-name">{clean}</span>
                                {v6 && <span className="qp-chip">IPv6</span>}
                              </span>
                              <span className="qp-meta">
                                <span className={`qp-delay ${tileDelayClass(node.delay)}`}>
                                  <span className="qp-bars" aria-hidden="true">
                                    {[1, 2, 3, 4].map(i => <i key={i} className={i <= bars ? 'on' : ''} />)}
                                  </span>
                                  {tileDelayText(node.delay)}
                                </span>
                                {node.active && <span className="qp-current">当前</span>}
                              </span>
                            </>
                          );
                        })()}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: SERVERS (NODES) */}
          {activeTab === 'servers' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="content-header" style={{ marginBottom: '4px', alignItems: 'center', gap: '16px' }}>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <h1 className="content-title" style={{ margin: 0 }}>节点列表</h1>
                  {/* 操作说明收进 ?：悬停（桌面）或点击显示 */}
                  <span className="help-pop" tabIndex={0} aria-label="操作说明">
                    <CircleHelp size={15} />
                    <span className="help-pop-body" role="tooltip">
                      <b>操作说明</b>
                      <span>单击选中，再点一次取消</span>
                      <span>点复选框、Ctrl+点击或拖动框选：多选</span>
                      <span><kbd>Enter</kbd> 启用选中的节点（仅选中一个时）</span>
                      <span><kbd>Ctrl+A</kbd> 全选 · <kbd>Esc</kbd> 取消选择</span>
                      <span><kbd>Ctrl+R</kbd> 测速选中节点（<kbd>Ctrl+A</kbd> 后按即全部测速）</span>
                      <span><kbd>Delete</kbd> 删除选中节点</span>
                      <span><kbd>Ctrl+C</kbd> 复制当前节点链接 · <kbd>Ctrl+V</kbd> 从剪贴板导入</span>
                      <span className="help-pop-note">切换节点主要在仪表盘的快速选择里进行</span>
                    </span>
                  </span>
                  {selectedNodeIds.length > 0 && (
                    <span className="sel-count">已选 {selectedNodeIds.length}</span>
                  )}
                </div>
                <button
                  className="win11-btn primary icon-only"
                  onClick={() => setShowAddNodeModal(true)}
                  title="添加节点"
                  aria-label="添加节点"
                >
                  <Plus size={16} />
                </button>
              </div>

              {/* Nodes List */}
              <div
                ref={nodeListRef}
                onMouseDown={handleListMouseDown}
                style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px', userSelect: dragBox ? 'none' : undefined, paddingBottom: '24px' }}
              >
                {filteredNodes.map(node => {
                  const isSwitching = switchingNodeId === node.id;
                  const isSelected = selectedNodeIds.includes(node.id);
                  return (
                    <div
                      key={node.id}
                      data-node-id={node.id}
                      className="win11-card"
                      onClick={(e) => {
                        if (suppressClickRef.current) return;
                        if (e.ctrlKey || e.metaKey) {
                          // Ctrl+点击：加选/减选，不改变当前连接节点
                          setSelectedNodeIds(ids => ids.includes(node.id)
                            ? ids.filter(x => x !== node.id)
                            : [...ids, node.id]);
                          return;
                        }
                        if (e.shiftKey && selectedNodeIds.length > 0) {
                          // Shift+点击：范围多选
                          const lastId = selectedNodeIds[selectedNodeIds.length - 1];
                          const lastIdx = filteredNodes.findIndex(n => n.id === lastId);
                          const curIdx = filteredNodes.findIndex(n => n.id === node.id);
                          if (lastIdx !== -1 && curIdx !== -1) {
                            const [start, end] = lastIdx < curIdx ? [lastIdx, curIdx] : [curIdx, lastIdx];
                            const rangeIds = filteredNodes.slice(start, end + 1).map(n => n.id);
                            setSelectedNodeIds(Array.from(new Set([...selectedNodeIds, ...rangeIds])));
                            return;
                          }
                        }
                        // 单击只选中，再点一次取消；选中单个后按 Enter 才启用（主要切换入口在主页快速选择）
                        setSelectedNodeIds(ids => (ids.length === 1 && ids[0] === node.id) ? [] : [node.id]);
                      }}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '12px 18px',
                        cursor: 'pointer',
                        // 蓝色描边只表示「选中」（编辑 / 批量操作）；当前启用的节点只用「活动」标签标出
                        border: isSelected
                          ? '1px solid var(--accent)'
                          : '1px solid var(--border-subtle)',
                        boxShadow: isSelected
                          ? '0 0 0 1px var(--accent)'
                          : 'var(--shadow-card)',
                        background: isSelected
                          ? 'var(--accent-subtle)'
                          : 'var(--bg-card)',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1 }}>
                        {/* 节点列表主要用来编辑 / 批量操作：用复选框表示选中，不用单选圆点（启用节点在主页快速选择） */}
                        <div
                          role="checkbox"
                          aria-checked={isSelected}
                          title={isSelected ? '取消选择' : '加入选择'}
                          onClick={(e) => {
                            // 复选框：加选 / 减选（多选），不影响其它已选节点
                            e.stopPropagation();
                            if (suppressClickRef.current) return;
                            setSelectedNodeIds(ids => ids.includes(node.id)
                              ? ids.filter(x => x !== node.id)
                              : [...ids, node.id]);
                          }}
                          style={{
                          width: '16px',
                          height: '16px',
                          cursor: 'pointer',
                          flexShrink: 0,
                          borderRadius: '4px',
                          border: isSelected ? '1px solid var(--accent)' : '1.5px solid var(--border-default)',
                          backgroundColor: isSelected ? 'var(--accent)' : 'transparent',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          transition: 'all 0.15s ease'
                        }}>
                          {isSelected && (
                            <svg width="10" height="10" viewBox="0 0 12 12" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2.5 6.5l2.5 2.5 4.5-5" /></svg>
                          )}
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className={`proto-badge proto-${node.protocol.toLowerCase()}`}>{protoLabel(node)}</span>
                            <strong style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{node.name}</strong>
                            {node.active && (
                              <span style={{
                                fontSize: '10px',
                                fontWeight: 600,
                                color: '#22c55e',
                                background: 'rgba(34, 197, 94, 0.12)',
                                border: '1px solid rgba(34, 197, 94, 0.4)',
                                padding: '1px 6px',
                                borderRadius: '3px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                lineHeight: '1.2'
                              }}>
                                活动
                              </span>
                            )}
                            {isSwitching && (
                              <span style={{ fontSize: '11px', color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <RefreshCw size={11} className="spin" /> 切换中…
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                            {node.address}:{node.port} · 安全: {node.security} · 传输: {node.network}
                          </div>
                        </div>
                      </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                      {(node.delay > 0 || node.delay === -2) && (
                        <span className={`latency-pill ${node.delay > 0 && node.delay < 300 ? 'latency-good' : node.delay < 800 ? 'latency-medium' : 'latency-none'}`} style={{ fontSize: '12px' }}>
                          <Zap size={13} />
                          {node.delay > 0 ? `${node.delay} ms` : '超时'}
                        </span>
                      )}

                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          className="win11-btn"
                          style={{ height: '28px', padding: '0 8px' }}
                          onClick={(e) => openEditNode(node, e)}
                          title="编辑节点"
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          className="win11-btn"
                          style={{ height: '28px', padding: '0 8px' }}
                          onClick={(e) => handlePingSingleNode(node.id, e)}
                          title="真连接测速"
                        >
                          <Gauge size={12} />
                        </button>
                        <button
                          className="win11-btn danger"
                          style={{ height: '28px', padding: '0 8px' }}
                          onClick={(e) => handleDeleteNode(node.id, e)}
                          title="删除节点"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
              </div>
            </div>
          )}

          {/* TAB 3: ROUTING */}
          {activeTab === 'routing' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div className="content-header">
                <div>
                  <h1 className="content-title">路由与分流规则</h1>
                  <p className="content-subtitle">智能域名解析与流量分流（基于 GEOIP & GEOSITE）</p>
                </div>
              </div>

              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>全局路由模式</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                  <div
                    onClick={() => handleRoutingChange('bypass-cn')}
                    style={{
                      padding: '16px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      border: shownMode === 'bypass-cn' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: shownMode === 'bypass-cn' ? 'var(--accent-subtle)' : 'var(--bg-card)'
                    }}
                  >
                    <h4 style={{ fontSize: '13px', fontWeight: 600 }}>绕过大陆 (GFWList)</h4>
                    <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      国内 IP 与主流国内域名直连，被屏蔽的国际网站自动通过节点代理转发。
                    </p>
                  </div>

                  <div
                    onClick={() => handleRoutingChange('global')}
                    style={{
                      padding: '16px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      border: shownMode === 'global' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: shownMode === 'global' ? 'var(--accent-subtle)' : 'var(--bg-card)'
                    }}
                  >
                    <h4 style={{ fontSize: '13px', fontWeight: 600 }}>全局代理 (Global)</h4>
                    <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      全部外部流量强制通过当前选中节点代理。
                    </p>
                  </div>

                  <div
                    onClick={() => handleRoutingChange('direct')}
                    style={{
                      padding: '16px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      border: shownMode === 'direct' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: shownMode === 'direct' ? 'var(--accent-subtle)' : 'var(--bg-card)'
                    }}
                  >
                    <h4 style={{ fontSize: '13px', fontWeight: 600 }}>全局直连 (Direct)</h4>
                    <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      不通过代理服务器，直接使用本地宽带直连访问互联网。
                    </p>
                  </div>
                </div>
              </div>

              {/* Domain Rule Cards */}
              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>预设规则集开关</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {[
                    { title: '绕过局域网私有网段 (Private IPs)', desc: '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 走直连', active: true },
                    { title: '拦截常见广告与恶意跟踪追踪 (AdBlock)', desc: 'geosite:category-ads-all 直接阻断 (Block)', active: true },
                    { title: 'AI 智能助手服务优化 (OpenAI, Claude, Gemini)', desc: '强制锁定特定专线低延迟节点路由', active: true },
                    { title: '国外流媒体解锁路由 (Netflix / Disney+)', desc: '自动匹配支持原生 IP 解锁的目标节点', active: false }
                  ].map((rule, idx) => (
                    <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>{rule.title}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>{rule.desc}</div>
                      </div>
                      <label className="win11-toggle">
                        <input type="checkbox" defaultChecked={rule.active} />
                        <span className="toggle-track"><span className="toggle-thumb" /></span>
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: LOGS */}
          {activeTab === 'logs' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: '100%' }}>
              <div className="content-header" style={{ marginBottom: 0 }}>
                <div>
                  <h1 className="content-title">实时运行日志</h1>
                  <p className="content-subtitle">查看代理核心的连接追踪、分流判定与警告异常</p>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="win11-btn" onClick={() => ClearLogs()}>
                    <Trash2 size={13} />
                    <span>清空日志</span>
                  </button>
                  <button className="win11-btn primary" onClick={() => refreshAllData()}>
                    <RefreshCw size={13} />
                    <span>刷新</span>
                  </button>
                </div>
              </div>

              <div className="win11-card" style={{ flex: 1, padding: '14px', background: 'rgba(15, 15, 15, 0.85)', color: '#eaeaea', fontFamily: 'Consolas, monospace', fontSize: '12px', overflowY: 'auto', borderRadius: '8px', minHeight: '380px' }}>
                {logs.map(log => (
                  <div key={log.id} style={{ display: 'flex', gap: '10px', lineHeight: '1.7' }}>
                    <span style={{ color: '#888' }}>[{log.time}]</span>
                    <span style={{
                      color: log.level === 'error' ? '#f85149' : log.level === 'warn' ? '#d29922' : '#58a6ff',
                      fontWeight: 600,
                      width: '45px'
                    }}>
                      {log.level.toUpperCase()}
                    </span>
                    <span style={{ color: '#e6edf3' }}>{log.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 6: SETTINGS */}
          {activeTab === 'settings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="content-header">
                <div>
                  <h1 className="content-title">首选项设置</h1>
                  <p className="content-subtitle">配置本地监听端口、DNS 解析与系统集成</p>
                </div>
                <button className="win11-btn primary" onClick={handleSaveSettings}>
                  <Check size={14} />
                  <span>保存设置</span>
                </button>
              </div>

              {/* Group 1 */}
              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>本地代理端口</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px' }}>
                  <div className="form-group">
                    <label className="form-label">SOCKS5 代理端口</label>
                    <input
                      type="number"
                      className="win11-input"
                      value={settings.socksPort}
                      onChange={e => setLocalSettings({ ...settings, socksPort: parseInt(e.target.value, 10) || 10808 })}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">HTTP / HTTPS 代理端口</label>
                    <input
                      type="number"
                      className="win11-input"
                      value={settings.httpPort}
                      onChange={e => setLocalSettings({ ...settings, httpPort: parseInt(e.target.value, 10) || 10809 })}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 500 }}>允许来自局域网的连接 (Allow LAN)</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>让同局域网设备通过本机 IP 代理上网</div>
                  </div>
                  <label className="win11-toggle">
                    <input
                      type="checkbox"
                      checked={settings.allowLan}
                      onChange={e => setLocalSettings({ ...settings, allowLan: e.target.checked })}
                    />
                    <span className="toggle-track"><span className="toggle-thumb" /></span>
                  </label>
                </div>
              </div>

              {/* Group 2 */}
              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>核心引擎与多路复用</h3>
                <div className="form-group">
                  <label className="form-label">底层 Core 类型</label>
                  <select
                    className="win11-input"
                    value={settings.coreType}
                    onChange={e => setLocalSettings({ ...settings, coreType: e.target.value })}
                  >
                    <option value="Xray-core">Xray-core (推荐，协议支持全)</option>
                    <option value="V2Ray-core">V2Ray-core (传统稳定版)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 500 }}>启用 MUX 多路复用 (Multiplexing)</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>合并 TCP 连接，降低握手延迟</div>
                  </div>
                  <label className="win11-toggle">
                    <input
                      type="checkbox"
                      checked={settings.muxEnabled}
                      onChange={e => setLocalSettings({ ...settings, muxEnabled: e.target.checked })}
                    />
                    <span className="toggle-track"><span className="toggle-thumb" /></span>
                  </label>
                </div>
              </div>

              {/* Group 3 */}
              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>DNS 服务器设置</h3>
                <div className="form-group">
                  <label className="form-label">远程与直连 DNS 服务器地址 (英文逗号分隔)</label>
                  <input
                    type="text"
                    className="win11-input"
                    value={settings.dnsServers}
                    onChange={e => setLocalSettings({ ...settings, dnsServers: e.target.value })}
                  />
                </div>
              </div>

              {/* Group 4: 系统托盘与开机启动 */}
              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>系统托盘与开机启动</h3>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 500 }}>开机自动启动</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      登录 Windows 后自动启动 KNcloud-WIN，方便随时接管代理
                    </div>
                  </div>
                  <label className="win11-toggle">
                    <input
                      type="checkbox"
                      checked={!!settings.autoStart}
                      onChange={e => setLocalSettings({ ...settings, autoStart: e.target.checked })}
                    />
                    <span className="toggle-track"><span className="toggle-thumb" /></span>
                  </label>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 500 }}>自动更新订阅</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      登录官网账户后，每周自动刷新套餐流量并同步最新节点
                    </div>
                  </div>
                  <select
                    className="win11-input"
                    style={{ width: '140px' }}
                    value={(settings.subUpdateHours || 0) < 0 ? -1 : 0}
                    onChange={e => setLocalSettings({ ...settings, subUpdateHours: parseInt(e.target.value, 10) })}
                  >
                    <option value={0}>每周（默认）</option>
                    <option value={-1}>关闭</option>
                  </select>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 500 }}>关闭窗口时最小化到托盘</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      关闭主窗口后程序继续在右下角托盘运行；右键托盘图标可切换模式、切换节点或退出
                    </div>
                  </div>
                  <label className="win11-toggle">
                    <input
                      type="checkbox"
                      checked={!!settings.minimizeToTray}
                      onChange={e => setLocalSettings({ ...settings, minimizeToTray: e.target.checked })}
                    />
                    <span className="toggle-track"><span className="toggle-thumb" /></span>
                  </label>
                </div>
              </div>

              {/* Group 5: 关于与更新（纯手动：点「检查更新」才联网，点「立即更新」才下载安装） */}
              <div className="win11-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>关于与更新</h3>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 500 }}>当前版本 {appVersion || '…'}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      从 GitHub Releases 检查新版本；不会自动下载或安装，配置与日志在更新时保持不变
                    </div>
                  </div>
                  <button className="win11-btn" onClick={handleCheckUpdate} disabled={updChecking || updBusy} style={{ flex: 'none' }}>
                    <RefreshCw size={13} className={updChecking ? 'spin' : ''} />
                    <span>{updChecking ? '检查中…' : '检查更新'}</span>
                  </button>
                </div>

                {updInfo && (
                  <div className="update-result">
                    <div className={`update-msg ${updInfo.hasUpdate ? 'has-update' : ''}`}>
                      {updInfo.hasUpdate
                        ? `发现新版本 ${updInfo.latestVersion}${updInfo.publishedAt ? '（' + updInfo.publishedAt.slice(0, 10) + '）' : ''}`
                        : (updInfo.message || '已是最新版本') + (updInfo.latestVersion && !updInfo.hasUpdate ? ` · 最新发布 ${updInfo.latestVersion}` : '')}
                    </div>
                    {updInfo.hasUpdate && updInfo.notes && (
                      <pre className="update-notes">{updInfo.notes}</pre>
                    )}
                    {updInfo.hasUpdate && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                        <button className="win11-btn primary" onClick={handleStartUpdate} disabled={updBusy}>
                          <ArrowDownLeft size={13} />
                          <span>{updBusy ? '更新中…' : '立即更新'}</span>
                        </button>
                        {updInfo.assetSize > 0 && (
                          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                            安装包 {(updInfo.assetSize / 1048576).toFixed(1)} MB · 完成后自动重启
                          </span>
                        )}
                        {updInfo.releaseUrl && (
                          <button type="button" className="core-link" onClick={() => BrowserOpenURL(updInfo.releaseUrl)}>查看发布页</button>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {updProgress.stage !== 'idle' && (
                  <div className="update-progress">
                    {updBusy && (
                      <div className="simple-account-bar update-bar">
                        <div style={{ width: Math.max(2, Math.min(100, updProgress.percent || 0)) + '%' }} />
                      </div>
                    )}
                    <div className={`update-progress-msg ${updProgress.stage === 'error' ? 'error' : ''}`}>{updProgress.message}</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Modal: Add Node Dialog */}
      {showAddNodeModal && (
        <div className="modal-overlay" onClick={() => { setShowAddNodeModal(false); resetNodeForm(); }}>
          <div className="win11-dialog" onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>{editingNodeId ? '编辑节点' : '添加节点'}</h2>
            
            <div className="form-group">
              <label className="form-label">节点名称 (备注)</label>
              <input
                type="text"
                className="win11-input"
                placeholder="例如: 日本东京 01"
                value={newNode.name}
                onChange={e => setNewNode({ ...newNode, name: e.target.value })}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label className="form-label">协议类型</label>
                <select
                  className="win11-input"
                  value={newNode.protocol}
                  onChange={e => setNewNode({ ...newNode, protocol: e.target.value })}
                >
                  <option value="VLESS">VLESS</option>
                  <option value="VMess">VMess</option>
                  <option value="Trojan">Trojan</option>
                  <option value="Hysteria2">Hysteria2</option>
                  <option value="AnyTLS">AnyTLS</option>
                  <option value="Shadowsocks">Shadowsocks</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">传输协议 (Network)</label>
                <select
                  className="win11-input"
                  value={newNode.network}
                  onChange={e => setNewNode({ ...newNode, network: e.target.value })}
                >
                  <option value="tcp">TCP</option>
                  <option value="ws">WebSocket (WS)</option>
                  <option value="grpc">gRPC</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label className="form-label">服务器地址 (Domain / IP)</label>
                <input
                  type="text"
                  className="win11-input"
                  placeholder="hk.example.com"
                  value={newNode.address}
                  onChange={e => setNewNode({ ...newNode, address: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label className="form-label">端口 (Port)</label>
                <input
                  type="number"
                  className="win11-input"
                  value={newNode.port}
                  onChange={e => setNewNode({ ...newNode, port: e.target.value })}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">用户 ID / 密码 (UUID / Password)</label>
              <input
                type="text"
                className="win11-input"
                placeholder="UUID 字符串或连接密钥"
                value={newNode.uuid}
                onChange={e => setNewNode({ ...newNode, uuid: e.target.value })}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
              <button className="win11-btn" onClick={() => { setShowAddNodeModal(false); resetNodeForm(); }}>取消</button>
              <button className="win11-btn primary" onClick={handleCreateNode}>{editingNodeId ? '保存修改' : '添加并保存'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Import Share Links */}
      {dragBox && (
        <div style={{
          position: 'fixed', left: dragBox.left, top: dragBox.top, width: dragBox.width, height: dragBox.height,
          border: '1px solid var(--accent)', background: 'rgba(0, 120, 212, 0.15)', borderRadius: '2px',
          pointerEvents: 'none', zIndex: 900
        }} />
      )}

      {deleteConfirmIds && (
        <div className="modal-overlay" onClick={() => setDeleteConfirmIds(null)}>
          <div className="win11-dialog" onClick={e => e.stopPropagation()} style={{ maxWidth: '380px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>删除节点</h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '8px 0 4px' }}>
              {deleteConfirmIds.length === 1
                ? `确定删除「${(nodes.find(n => n.id === deleteConfirmIds[0]) || {}).name || '该节点'}」吗？`
                : `确定删除选中的 ${deleteConfirmIds.length} 个节点吗？`}
              {nodes.some(n => n.active && deleteConfirmIds.includes(n.id)) && ' 其中包含当前正在使用的节点。'}
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '14px' }}>
              <button className="win11-btn" onClick={() => setDeleteConfirmIds(null)}>取消</button>
              <button className="win11-btn danger" onClick={confirmDeleteNodes}>删除</button>
            </div>
          </div>
        </div>
      )}

      {showImportModal && (
        <div className="modal-overlay" onClick={() => setShowImportModal(false)}>
          <div className="win11-dialog" onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>批量导入分享链接</h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 10px' }}>
              每行一条，支持 vmess:// vless:// trojan:// ss:// anytls:// hysteria2:// 链接，或直接粘贴 Base64 订阅内容。
            </p>
            <div className="form-group">
              <textarea
                className="win11-input"
                rows={8}
                placeholder={'vless://uuid@host:443?security=reality&type=grpc#节点名\nvmess://eyJ2IjoiMiIsLi4u\nss://YWVzLTI1Ni1nY206cGFzcw==@host:8388#SS节点'}
                value={importText}
                onChange={e => setImportText(e.target.value)}
                style={{ fontFamily: 'Consolas, monospace', fontSize: '12px', resize: 'vertical' }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
              <button className="win11-btn" onClick={() => setShowImportModal(false)}>取消</button>
              <button className="win11-btn primary" onClick={handleImportLinks}>解析并导入</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
