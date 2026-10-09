# KNcloud-WIN

基于 Wails + React + Xray-core 的 Windows 11 原生代理客户端（Fluent / Mica 视觉风格）。

## 功能

- **真实代理内核**：内置 Xray-core（嵌入编译，无需外部内核文件），支持 VLESS / VMess / Trojan / Shadowsocks / AnyTLS 节点，本地提供 SOCKS5 与 HTTP 代理入站
- **订阅管理**：真实拉取订阅链接（自动识别 Base64 / 明文分享链接列表），解析 vmess:// vless:// trojan:// ss:// hysteria2:// 链接（anytls:// 暂不支持，导入时跳过并记日志），自动过滤机场"流量信息/套餐到期"伪节点；支持订阅更新与删除
- **分享链接导入**：服务器页「导入分享链接」弹窗，支持每行一条批量导入或直接粘贴 Base64 订阅内容
- **节点测速**：真实 TCP 拨测延迟（单节点 / 全部）
- **路由分流**：绕过大陆（geoip:cn / geosite:cn 直连，内置 geoip.dat / geosite.dat，首次运行自动释放到配置目录）、全局代理、全局直连；内置广告拦截规则（geosite:category-ads-all → 阻断）
- **真实流量统计**：从内核 stats 计数器每秒采样，实时速率与累计流量
- **系统代理**：一键接管/还原 Windows 系统代理；应用退出时自动还原，不留死代理
- **持久化**：节点、订阅、设置、累计流量保存至 `%APPDATA%\KNcloud\config.json`，重启自动恢复
- **端口冲突检测**：内核启动前预检端口占用并给出中文提示（可在首选项中修改端口）

## 构建

```bash
wails build        # 产物位于 build/bin/KNcloud-WIN.exe
```

开发模式：`wails dev`（前端热更新，Go 方法可在 http://localhost:34115 调试）。

## 说明

- Hysteria2 节点可导入展示，但 Xray 内核不支持其代理转发，启动该类节点会给出明确错误
- AnyTLS：Xray 没有 AnyTLS 出站，程序内置进程内 AnyTLS 协议桥（sing-anytls，本地 SOCKS5，TCP + UDP-over-TCP），Xray 仍负责分流与统计
- TUN 模式（需管理员）：常驻虚拟网卡 KNcloud-TAP + 进程内 gVisor 协议栈，与分流策略组合——「绕过大陆」时中国大陆网段直接写成物理网卡路由（SSTap「跳过中国 IP」同款，国内流量不进隧道），「全局」时除局域网外全部走代理；也支持 SSTap 的 `.rules` 规则文件（`sstap:<文件路径>`）。TUN 运行中可直接切换策略与节点，不断网
- 默认端口 SOCKS5 `10808` / HTTP `10809`，与其他代理软件冲突时请在「首选项设置」中修改
- 首选项中开启「自动启动内核」后，应用启动即自动恢复上次的节点与系统代理状态
## Windows 发布签名

Windows SmartScreen 可能会对未签名或信誉不足的新程序显示“发布者未知”警告。正式版本由 GitHub Actions 使用 Windows Authenticode 代码签名证书签名；发布标签构建在签名配置缺失时会直接失败，避免发布未签名的 EXE。

在仓库的 **Settings → Secrets and variables → Actions** 中配置：

- `WINDOWS_CERTIFICATE_BASE64`：`.pfx` 证书文件的 Base64 内容
- `WINDOWS_CERTIFICATE_PASSWORD`：`.pfx` 密码

证书私钥不会提交到仓库。签名可以显示可信发布者，但 SmartScreen 信誉仍可能需要一段时间建立。
