# KNcloud for macOS（KNcloud-Macos）

基于 Wails v2 + React + 内嵌 Xray-core 的 macOS 代理客户端，由 Windows 版 [KNcloud-WIN](https://github.com/dagata1/KNcloud-WIN) 移植而来，功能一致：系统代理三种分流模式 + TUN 全局接管、订阅与账户、节点测速、AnyTLS 桥、在线更新。

- 支持 **Apple Silicon（M 系列）与 Intel** 两种 Mac（universal 通用二进制），macOS 12 Monterey 及以上
- 产物：`KNcloud-macOS-<版本>.dmg`（拖入「应用程序」安装）与 `KNcloud-macOS-<版本>.zip`（在线更新用，附 `.sha256`）

## 安装

1. 在 [Releases](https://github.com/dagata1/KNcloud-Macos/releases) 下载 `KNcloud-macOS-<版本>.dmg`（或在 Actions 的构建记录里下载 `KNcloud-macOS-universal` 工件）。
2. 双击打开 dmg，把 **KNcloud** 拖到 **Applications（应用程序）**。
3. 首次打开会被 Gatekeeper 拦住（见下一节），按说明放行一次即可。

### Gatekeeper（「无法验证开发者」/「已损坏」）

本项目目前**没有 Apple Developer ID 证书**，应用只做了 ad-hoc 签名（`codesign -s -`），也没有经过 Apple 公证（notarization）。因此第一次打开时 macOS 会提示「无法打开，因为无法验证开发者」或「已损坏，无法打开」。任选一种方式放行：

- **方法一（推荐）**：在「应用程序」里**右键（或按住 Control 点按）KNcloud → 打开**，在弹窗里再点「打开」。只需做一次。
  macOS 15 Sequoia 起右键打开不再出现「打开」按钮：先双击一次，然后到 **系统设置 → 隐私与安全性**，在页面底部点「仍要打开」。
- **方法二（终端）**：去掉下载隔离标记后正常双击打开：

  ```bash
  xattr -dr com.apple.quarantine /Applications/KNcloud.app
  ```

> 想彻底去掉这个提示，需要付费的 Apple Developer ID（99 美元/年）：用 Developer ID Application 证书签名（`codesign --options runtime --timestamp`）并 `xcrun notarytool submit` 公证、`xcrun stapler staple`。CI 里预留了位置，有证书后把证书与 App 专用密码配置为仓库 Secrets 即可。

## 使用与权限提示

| 功能 | macOS 上的实现 | 会不会弹权限 |
| --- | --- | --- |
| 系统代理（绕过大陆 / 全局代理 / 全局直连） | `networksetup` 为所有启用中的网络服务设置 HTTP / HTTPS / SOCKS 代理，退出时还原 | 管理员账户不弹；**标准（非管理员）账户无法修改系统代理** |
| TUN 模式 | utun 虚拟网卡 + 进程内 gVisor 协议栈（与 Windows 同一套转发代码） | **首次开启时弹出系统管理员密码框**（见下） |
| 开机（登录）自启 | `~/Library/LaunchAgents/top.kncloud.macos.plist` | macOS 13+ 会弹一次「已添加登录项」通知；可在 系统设置 → 通用 → 登录项 中管理 |
| 凭证加密 | 随机密钥存「登录钥匙串」（项目名 `top.kncloud.macos`），账户令牌用 AES-256-GCM 加密后落盘 | 一般不弹；钥匙串被锁时退回配置目录下 0600 权限的密钥文件 |
| `kncloud://` 一键登录/订阅 | Info.plist 声明 URL Scheme | 浏览器会询问是否打开 KNcloud |
| 配置与日志 | `~/Library/Application Support/KNcloud/` | — |

### TUN 模式的管理员授权

创建 utun、修改路由表与系统 DNS 必须 root 权限，而图形界面程序不应整个以 root 运行。KNcloud 的做法：

1. 第一次开启 TUN 时，系统弹出标准的管理员授权框（「KNcloud 需要管理员权限来开启 TUN 模式…」），输入开机密码；
2. 授权后以 root 启动一个**特权助手**（就是同一个程序：`KNcloud --tun-helper …`），它只负责：创建 utun 并把描述符交给主程序、增删路由（`/sbin/route`）、设置/还原 DNS（`networksetup`）、刷新 DNS 缓存；
3. 助手只接受本用户的连接（内核校验对端 uid），主程序退出（包括崩溃）后助手会自动撤销自己加过的路由、还原 DNS 并退出；
4. 每次启动 KNcloud 后第一次开 TUN 会再要一次密码（助手随主程序退出）。点「取消」则 TUN 不开启，系统代理模式不受影响。

TUN 开启后：默认路由（0/1 + 128/1）、IPv6 全局单播 2000::/3、DNS 劫持地址 198.18.0.2 进 utun；节点服务器 IP、DNS 服务器与局域网/私网段经物理网关直连；所有网络服务的 DNS 临时改为 198.18.0.2，由 TUN 内的 DNS 中继经物理网卡查询公共 DNS（防污染、防回环）。关闭 TUN 或退出程序即全部还原。

### 菜单栏 / Dock（替代 Windows 托盘）

macOS 版不在右上角菜单栏放状态图标：Windows 用的 systray 库在 macOS 上需要独占主线程运行自己的 `NSApp run`，与 Wails v2 冲突，而 Wails v2 本身没有状态栏图标 API。因此：

- 程序保留 **Dock 图标**；顶部菜单栏的 **「代理」菜单** 提供 Windows 托盘的全部功能：状态、显示主界面（⌘1）、更新订阅（⌘U）、绕过大陆 / 全局代理 / 全局直连 / TUN 模式、切换节点、重启内核（⌘R）；
- 点窗口右上角的关闭按钮（开启「关闭窗口时隐藏到后台」时）只隐藏应用，**点 Dock 图标即可恢复**；
- **⌘Q**、Dock 右键「退出」、注销/关机都会真正退出，并还原系统代理、撤销 TUN。

## 与 Windows 版的差异

- **没有 WFP**：Windows 版可选的 WFP DNS 防泄漏过滤在 macOS 上没有对应物，改用路由级防护（系统 DNS 指向 198.18.0.2 且该地址进 TUN；IPv6 2000::/3 进 TUN）。
- **没有原生 badvpn / SSTap TAP 引擎**（`KNCLOUD_NATIVE_TUN`）：macOS 上 TUN 恒为内置 gVisor 引擎；`wintun.dll`、`badvpn-tun2socks` 不随 macOS 版发布。
- **没有绿色版**：.app 内部不可写（会破坏签名），配置固定在 `~/Library/Application Support/KNcloud/`；首次启动不会读取 Windows 的配置。
- **BSD 路由没有 metric**：靠最长前缀匹配实现分流，效果与 Windows 相同；若已有其它 VPN 占用了同样的网段路由，KNcloud 不会覆盖也不会删除它。
- **系统代理**同时设置 HTTP、HTTPS 与 SOCKS 三项（Windows 只有 HTTP），作用于全部启用中的网络服务（Wi‑Fi、以太网、USB 网卡等）。
- **在线更新**：从本仓库 Releases 下载 `KNcloud-macOS-<tag>.zip` 并校验 SHA256，替换当前 .app 后自动重启；.app 所在目录不可写（或从 dmg 里直接运行）时提示手动下载。
- **窗口**：沿用 Windows 版的自绘标题栏（最小化 / 最大化 / 关闭按钮在右上角），没有 macOS 红绿灯按钮；Mica 毛玻璃效果改为不透明背景。

## 从源码构建

需要 macOS 12+、Xcode Command Line Tools、Go 1.25、Node 24、Wails CLI v2.15.0：

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
cd frontend && npm ci && cd ..
wails build -platform darwin/universal
cp geo/geoip.dat geo/geosite.dat build/bin/KNcloud.app/Contents/Resources/
codesign --force --deep -s - build/bin/KNcloud.app
```

隐藏命令行入口（CI 冒烟用）：`KNcloud.app/Contents/MacOS/KNcloud --version`、`--core-selftest`（内嵌 Xray 起本地 SOCKS 并经它访问本地 HTTP 服务）。

## 持续集成（GitHub Actions，`.github/workflows/macos.yml`）

- **test**：macOS（Apple Silicon）与 macOS Intel 上 `go vet ./...`、`go test ./...`（含真实修改/还原系统代理的测试），以及 **TUN 冒烟测试**：免密 sudo 拉起特权助手 → 创建 utun → gVisor 转发 → 路由 → 用 `curl` 与 UDP 穿过 utun 访问本地测试服务、经 198.18.0.2 中继查询 DNS、改写并还原系统 DNS、撤销路由；
- **build**：`wails build -platform darwin/universal` → 打包 geo 数据 → ad-hoc 签名并校验 → 冒烟（`--core-selftest`，含 Rosetta 下的 x86_64 分支；无头启动 GUI 20 秒后用 AppleScript 退出，检查系统代理被还原）→ 生成 `.zip`/`.sha256`/`.dmg` 工件；推送 `v*` 标签时自动创建 Release；
- **windows-check**：确认共享代码在 Windows 上仍能 `go vet` / `go build`（amd64 与 arm64）并跑单测。

## 仍需真机确认的部分

CI 没有显示器与人工交互，以下内容需要在真实 Mac 上看一眼：界面外观（字体、深浅色主题、无边框窗口拖动/缩放）、菜单栏「代理」菜单、管理员授权弹窗与取消路径、Gatekeeper 放行流程、`kncloud://` 链接从浏览器拉起、登录自启、在线更新替换 .app。
