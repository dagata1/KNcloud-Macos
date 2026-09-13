# KNcloud-WIN

基于 Wails + React + Xray-core 的 Windows 11 原生代理客户端（Fluent / Mica 视觉风格）。

## 功能

- **真实代理内核**：内置 Xray-core（嵌入编译，无需外部内核文件），支持 VLESS / VMess / Trojan / Shadowsocks 节点，本地提供 SOCKS5 与 HTTP 代理入站
- **订阅管理**：真实拉取订阅链接（自动识别 Base64 / 明文分享链接列表），解析 vmess:// vless:// trojan:// ss:// hysteria2:// 链接，自动过滤机场"流量信息/套餐到期"伪节点；支持订阅更新与删除
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
- 默认端口 SOCKS5 `10808` / HTTP `10809`，与其他代理软件冲突时请在「首选项设置」中修改
- 首选项中开启「自动启动内核」后，应用启动即自动恢复上次的节点与系统代理状态
