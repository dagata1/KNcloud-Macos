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
  Radio,
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
  Gauge
} from 'lucide-react';

import {
  GetNodes,
  SelectNode,
  AddNode,
  DeleteNode,
  PingNode,
  PingAllNodes,
  GetCoreStatus,
  ToggleCore,
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
import { EventsOn, WindowSetSize, WindowUnmaximise } from '../wailsjs/runtime';

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
  // 简易模式连接检测结果：idle=未连接, checking=检测中, ok=节点可用, fail=节点无效
  const [simpleNet, setSimpleNet] = useState('idle');
  // 简易模式自定义节点下拉是否展开
  const [nodeMenuOpen, setNodeMenuOpen] = useState(false);
  const [selectedProto, setSelectedProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isPingingAll, setIsPingingAll] = useState(false);

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
    minimizeToTray: true
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
  const [tunBusy, setTunBusy] = useState(false); // TUN 模式切换进行中

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
    return () => {
      if (typeof off === 'function') off();
    };
  }, []);

  // 关闭按钮的语义取决于「关闭窗口时最小化到托盘」开关
  const closeWindowTitle = settings.minimizeToTray
    ? '关闭（最小化到系统托盘）'
    : '关闭并退出 KNcloud-WIN';

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
        if (curSettings.uiMode === 'simple') {
          setUiMode('simple');
          applyWindowSize('simple');
        }
      }
    } catch (e) {
      console.error("Init data load error", e);
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
  const handleToggleCore = async () => {
    const nextState = !status.running;
    try {
      await ToggleCore(nextState);
    } catch (e) {
      showToast('内核启动失败：' + (e?.message || e), 'error');
    }
    const updated = await GetCoreStatus();
    setStatus(updated);
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
    const next = status.routingMode === 'bypass-cn' ? 'direct' : 'bypass-cn';
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
      // 登录成功默认进入简洁模式（窗口同步切到紧凑尺寸）
      setUiMode('simple');
      applyWindowSize('simple');
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
      // 登录成功默认进入简洁模式（窗口同步切到紧凑尺寸）
      setUiMode('simple');
      applyWindowSize('simple');
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
    try {
      await SelectNode(id);
    } catch (e) {
      showToast('切换节点失败：' + (e?.message || e), 'error');
    }
    setNodes(await GetNodes());
    setStatus(await GetCoreStatus());
  };

  // 简易模式节点可用性自动检测：PingNode 在后端起临时内核，经该节点真实请求
  // 探测 URL，结果（delay > 0 可用 / -2 失败）同时回写到节点列表的延迟显示
  const checkSimpleNode = async () => {
    const cur = nodes.find(n => n.active);
    if (!cur) {
      setSimpleNet('fail');
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
    if ((status.routingMode || 'bypass-cn') === 'direct') {
      setSimpleNet('idle');
      return;
    }
    checkSimpleNode();
  }, [uiMode, status.routingMode, simpleActiveId]);

  // TUN 模式开关（虚拟网卡接管全部流量，与内核代理互斥；后端会自动停/恢复内核与系统代理）
  const handleToggleTun = async (on) => {
    if (tunBusy) return;
    setTunBusy(true);
    try {
      await SimpleConnect(on);
    } catch (e) {
      showToast(String(e?.message || e).replace(/^.*?: /, ''), 'error');
    }
    setStatus(await GetCoreStatus());
    setTunBusy(false);
  };

  const handleRoutingChange = async (mode) => {
    await SetRoutingMode(mode);
    const updated = await GetCoreStatus();
    setStatus(updated);
  };

  const handleSelectNode = async (id) => {
    await SelectNode(id);
    const updatedNodes = await GetNodes();
    setNodes(updatedNodes);
    const updated = await GetCoreStatus();
    setStatus(updated);
  };

  const handlePingSingleNode = async (id, e) => {
    e.stopPropagation();
    await PingNode(id);
    const updatedNodes = await GetNodes();
    setNodes(updatedNodes);
  };

  // Ctrl+R：真连接测速当前选中的节点（节点列表里 active 的那个）。
  // PingNode 在后端起临时内核经节点真实请求，耗时较长，用 ref 防止重复触发。
  const pingingActiveRef = useRef(false);
  const handlePingActiveNode = async () => {
    if (pingingActiveRef.current) return;
    const cur = nodes.find(n => n.active);
    if (!cur) {
      showToast('未选择节点，无法测速', 'error');
      return;
    }
    pingingActiveRef.current = true;
    showToast(`正在真连接测速「${cur.name}」…`);
    try {
      await PingNode(cur.id);
      const updated = await GetNodes();
      setNodes(updated);
      const n = updated.find(x => x.id === cur.id);
      if (n && n.delay > 0) {
        showToast(`「${n.name}」测速完成：${n.delay} ms`, 'success');
      } else {
        showToast(`「${cur.name}」测速超时或失败`, 'error');
      }
    } catch (e) {
      showToast('测速失败：' + (e?.message || e), 'error');
    }
    pingingActiveRef.current = false;
  };

  useEffect(() => {
    const onKey = async (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === 'r' || e.key === 'R')) {
        e.preventDefault(); // 拦截 WebView 默认的 Ctrl+R 刷新页面
        handlePingActiveNode();
        return;
      }
      // 节点列表页：Ctrl+C 复制选中节点的分享链接，Ctrl+V 导入剪贴板里的分享链接。
      // 焦点在输入框/文本域/下拉框时不拦截，保留原生复制粘贴行为
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      if (activeTab !== 'servers') return;
      const key = (e.key || '').toLowerCase();
      if (key !== 'c' && key !== 'v') return;
      const t = e.target;
      const tag = ((t && t.tagName) || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || (t && t.isContentEditable)) return;
      e.preventDefault();
      if (key === 'c') {
        const cur = nodes.find(n => n.active);
        if (!cur) {
          showToast('未选择节点，无法复制', 'error');
          return;
        }
        try {
          await CopyNodeShareLink(cur.id);
          showToast(`已复制「${cur.name}」的分享链接到剪贴板`, 'success');
        } catch (err) {
          showToast('复制失败：' + (err?.message || err), 'error');
        }
      } else {
        try {
          const count = await ImportNodesFromClipboard();
          if (count > 0) {
            setNodes(await GetNodes());
            showToast(`已从剪贴板导入 ${count} 个节点`, 'success');
          }
        } catch (err) {
          showToast('导入失败：' + (err?.message || err), 'error');
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const handlePingAll = async () => {
    setIsPingingAll(true);
    const res = await PingAllNodes();
    setNodes(res);
    setIsPingingAll(false);
  };

  const handleDeleteNode = async (id, e) => {
    e.stopPropagation();
    await DeleteNode(id);
    const updatedNodes = await GetNodes();
    setNodes(updatedNodes);
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

  const handleSaveSettings = async () => {
    await SaveSettings(settings);
    showToast('首选项已成功保存！', 'success');
  };

  // Filtered nodes
  const filteredNodes = nodes;

  // 仪表盘推荐节点：按真连接延迟排序（已测速升序 → 超时 → 未测速垫底），取前 3 个
  const quickPickNodes = [...nodes].sort((a, b) => {
    const rank = (d) => (d > 0 ? 0 : d === -2 ? 1 : 2);
    if (rank(a.delay) !== rank(b.delay)) return rank(a.delay) - rank(b.delay);
    return rank(a.delay) === 0 ? a.delay - b.delay : 0;
  });

  // 登录页与简洁模式同尺寸（420x640）；登录成功后由模式切换逻辑控制窗口
  useEffect(() => {
    if (account && !account.loggedIn) applyWindowSize('simple');
  }, [account && account.loggedIn]);

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

  // ---------------- 简易模式（点击即用，无复杂设置） ----------------
  if (uiMode === 'simple') {
    const activeNode = nodes.find(n => n.active);
    // 简易模式的状态完全由分流策略决定（不再依赖 TUN 是否运行）
    const routing = status.routingMode || 'bypass-cn';
    const simpleOn = routing === 'bypass-cn';
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
                  : '链接成功'}
          </div>

          <div className="simple-speed">
            <span>↑ {status.upSpeed}</span>
            <span>↓ {status.downSpeed}</span>
          </div>

          <div className="simple-node-area" style={{ position: 'relative' }}>
            <label>代理节点</label>
            <button type="button" className="simple-node-trigger" onClick={() => setNodeMenuOpen(o => !o)}>
              {activeNode ? (
                <>
                  <span className={`proto-badge proto-${activeNode.protocol.toLowerCase()}`}>{activeNode.protocol}</span>
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
                <div className="simple-node-menu">
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
                      <span className={`proto-badge proto-${n.protocol.toLowerCase()}`}>{n.protocol}</span>
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
              </div>

              {account && account.loggedIn && (
                <div className="win11-card account-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {account.email}
                        </h4>
                        <span style={{ fontSize: '12px', color: 'var(--accent)', fontWeight: 600, padding: '2px 8px', borderRadius: '6px', background: 'var(--accent-subtle)' }}>
                          {account.planName || 'KNcloud 会员'}
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                        已用 {fmtGB(account.usedUp + account.usedDown)} / {account.transferEnable > 0 ? fmtGB(account.transferEnable) : '无限'} · {account.expire}
                        {subscriptions[0] && (
                          <span style={{ marginLeft: '12px', color: 'var(--text-tertiary)' }}>
                            上次同步: {subscriptions[0].updatedAt}
                          </span>
                        )}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button className="win11-btn" onClick={handleUpdateSubscription} disabled={syncing}>
                        <RefreshCw size={13} className={syncing ? 'spin' : ''} />
                        <span>{syncing ? '更新中...' : '更新订阅'}</span>
                      </button>
                      <button className="win11-btn danger" onClick={handleLogout}>
                        <span>退出登录</span>
                      </button>
                    </div>
                  </div>
                  <div className="simple-account-bar" style={{ marginTop: '14px' }}>
                    <div style={{
                      width: account.transferEnable > 0
                        ? Math.min(100, Math.round((account.usedUp + account.usedDown) * 100 / account.transferEnable)) + '%'
                        : '0%'
                    }} />
                  </div>
                </div>
              )}


              {/* Top Hero Status Banner：仅展示当前连接节点 + 策略/TUN 控制 */}
              <div className="win11-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '24px' }}>
                <div>
                  <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {status.activeNodeName === '未选择节点' ? '未选择节点' : `当前节点：${status.activeNodeName}`}
                  </h2>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    {status.activeNodeName === '未选择节点'
                      ? '请在服务器节点列表中选择一个节点'
                      : `${status.activeNodeProto}${status.tunnelMode ? ' · TUN 分流（大陆直连）' : ''}`}
                  </p>
                </div>

                {/* Routing policy radio + TUN mode switch */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>分流策略</span>
                  <div
                    className="segmented-control"
                    style={status.tunnelMode || tunBusy ? { opacity: 0.45, pointerEvents: 'none' } : null}
                    title={status.tunnelMode ? 'TUN 模式接管中，关闭 TUN 后可切换分流策略' : ''}
                  >
                    <button
                      className={`segment-btn ${status.routingMode === 'bypass-cn' ? 'active' : ''}`}
                      onClick={() => handleRoutingChange('bypass-cn')}
                    >
                      绕过大陆
                    </button>
                    <button
                      className={`segment-btn ${status.routingMode === 'global' ? 'active' : ''}`}
                      onClick={() => handleRoutingChange('global')}
                    >
                      全局代理
                    </button>
                    <button
                      className={`segment-btn ${status.routingMode === 'direct' ? 'active' : ''}`}
                      onClick={() => handleRoutingChange('direct')}
                    >
                      全局直连
                    </button>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '4px' }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>TUN 模式</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                        {status.tunnelMode ? '虚拟网卡接管全部流量 · 大陆直连' : '虚拟网卡接管全部流量（需管理员）'}
                      </div>
                    </div>
                    <label className="win11-toggle" title="开启后停用内核代理，由 TUN 虚拟网卡接管系统全部流量">
                      <input
                        type="checkbox"
                        checked={!!status.tunnelMode}
                        disabled={tunBusy}
                        onChange={e => handleToggleTun(e.target.checked)}
                      />
                      <span className="toggle-track"><span className="toggle-thumb" /></span>
                    </label>
                  </div>
                </div>
              </div>

              {/* 4 Metric Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
                <div className="win11-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    <span>实时上传</span>
                    <ArrowUpRight size={16} color="#0078d4" />
                  </div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '8px', color: 'var(--text-primary)' }}>
                    {status.upSpeed}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    累计上行: {status.totalUp}
                  </div>
                </div>

                <div className="win11-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    <span>实时下载</span>
                    <ArrowDownLeft size={16} color="#107c41" />
                  </div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '8px', color: 'var(--text-primary)' }}>
                    {status.downSpeed}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    累计下行: {status.totalDown}
                  </div>
                </div>

                <div className="win11-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    <span>Windows 系统代理</span>
                    <Radio size={16} color={status.systemProxy ? '#107c41' : '#888'} />
                  </div>
                  <div style={{ fontSize: '17px', fontWeight: 600, marginTop: '10px', color: status.systemProxy ? 'var(--accent)' : 'var(--text-secondary)' }}>
                    {status.systemProxy ? '已接管 (127.0.0.1)' : '未接管 (直连)'}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '6px' }}>
                    端口: 127.0.0.1:{settings.httpPort}
                  </div>
                </div>

                <div className="win11-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    <span>已载入服务器</span>
                    <Server size={16} color="#9b59b6" />
                  </div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '8px', color: 'var(--text-primary)' }}>
                    {nodes.length} 个节点
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    覆盖 {subscriptions.length} 个订阅源
                  </div>
                </div>
              </div>

              {/* Quick Node Switcher in Dashboard */}
              <div className="win11-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>推荐节点快速选择</h3>
                  <button className="win11-btn" onClick={() => setActiveTab('servers')}>
                    查看全部节点 ({nodes.length})
                  </button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                  {quickPickNodes.slice(0, 3).map(node => (
                    <div
                      key={node.id}
                      onClick={() => handleSelectNode(node.id)}
                      style={{
                        padding: '12px 14px',
                        borderRadius: '6px',
                        border: node.active ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                        background: node.active ? 'var(--accent-subtle)' : 'var(--bg-card)',
                        cursor: 'pointer',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className={`proto-badge proto-${node.protocol.toLowerCase()}`}>{node.protocol}</span>
                        {(node.delay > 0 || node.delay === -2) && (
                          <span className={`latency-pill ${node.delay > 0 && node.delay < 300 ? 'latency-good' : node.delay < 800 ? 'latency-medium' : 'latency-none'}`}>
                            <Zap size={12} /> {node.delay > 0 ? `${node.delay} ms` : '超时'}
                          </span>
                        )}
                      </div>
                      <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {node.name}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                        {node.address}:{node.port}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: SERVERS (NODES) */}
          {activeTab === 'servers' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="content-header" style={{ marginBottom: '8px' }}>
                <div>
                  <h1 className="content-title">节点列表</h1>
                  <p className="content-subtitle">查看、测速与切换代理节点（Ctrl+C 复制链接 · Ctrl+V 导入链接 · Ctrl+R 测速）</p>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="win11-btn" onClick={handlePingAll} disabled={isPingingAll} title="Ctrl+R 可单独测速当前选中的节点">
                    <Zap size={14} />
                    <span>全部真连接测速</span>
                  </button>
                  <button className="win11-btn" onClick={() => setShowImportModal(true)}>
                    <FolderInput size={14} />
                    <span>导入分享链接</span>
                  </button>
                  <button className="win11-btn primary" onClick={() => setShowAddNodeModal(true)}>
                    <Plus size={14} />
                    <span>添加节点</span>
                  </button>
                </div>
              </div>



              {/* Nodes List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                {filteredNodes.map(node => (
                  <div
                    key={node.id}
                    className="win11-card"
                    onClick={() => handleSelectNode(node.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 18px',
                      cursor: 'pointer',
                      border: node.active ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: node.active ? 'var(--accent-subtle)' : 'var(--bg-card)'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1 }}>
                      <div style={{
                        width: '18px',
                        height: '18px',
                        borderRadius: '50%',
                        border: node.active ? '5px solid var(--accent)' : '2px solid var(--border-default)',
                        backgroundColor: 'transparent'
                      }} />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className={`proto-badge proto-${node.protocol.toLowerCase()}`}>{node.protocol}</span>
                          <strong style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{node.name}</strong>
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
                ))}
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
                      border: status.routingMode === 'bypass-cn' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: status.routingMode === 'bypass-cn' ? 'var(--accent-subtle)' : 'var(--bg-card)'
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
                      border: status.routingMode === 'global' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: status.routingMode === 'global' ? 'var(--accent-subtle)' : 'var(--bg-card)'
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
                      border: status.routingMode === 'direct' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                      background: status.routingMode === 'direct' ? 'var(--accent-subtle)' : 'var(--bg-card)'
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
                    <option value="Sing-box">sing-box (高性能现代核心)</option>
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
                  <option value="VLESS">VLESS (推荐)</option>
                  <option value="VMess">VMess</option>
                  <option value="Trojan">Trojan</option>
                  <option value="Hysteria2">Hysteria2</option>
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
      {showImportModal && (
        <div className="modal-overlay" onClick={() => setShowImportModal(false)}>
          <div className="win11-dialog" onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>批量导入分享链接</h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 10px' }}>
              每行一条，支持 vmess:// vless:// trojan:// ss:// hysteria2:// 链接，或直接粘贴 Base64 订阅内容。
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
