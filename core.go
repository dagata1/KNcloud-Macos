package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// ensureGeoAssets 返回 geoip.dat / geosite.dat 所在目录（绿色版为 <exe目录>\bin）。
func ensureGeoAssets() (string, error) {
	ip, err := findResource("geoip.dat", "geo")
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(ip)
	if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err != nil {
		return "", fmt.Errorf("%w: 找不到 bin\\geosite.dat，请把压缩包完整解压后再运行", errResourceMissing)
	}
	return dir, nil
}

func xrayCoreVersion() string {
	return xcore.Version()
}

type ruleObj struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Network     string   `json:"network,omitempty"`
}

// buildCoreConfigJSON 根据当前节点 / 设置 / 路由模式生成 Xray 配置
func (a *App) buildCoreConfigJSON(node NodeItem) (string, error) {
	switch node.Protocol {
	case "VLESS", "VMess", "Trojan", "Shadowsocks", "HTTP", "SOCKS":
	case "AnyTLS":
		// Xray 没有 AnyTLS 出站，走进程内 AnyTLS 协议桥（见 anytls.go）：
		// 本配置里的 proxy 出站指向桥的本地 SOCKS 端口
		if a.bridgeAddr == "" {
			return "", fmt.Errorf("AnyTLS bridge is not running")
		}
	default:
		return "", fmt.Errorf("Xray core does not support %s (supported: VLESS/VMess/Trojan/Shadowsocks/HTTP/SOCKS/AnyTLS)", node.Protocol)
	}

	listen := "127.0.0.1"
	if a.settings.AllowLan {
		listen = "0.0.0.0"
	}
	sniffing := map[string]interface{}{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
	}
	// TUN 开启时 socks-in 承接整机流量：只嗅探 http/tls（QUIC 嗅探对首包要求高、
	// 失败时还要等超时；TUN 下 QUIC 按 IP 规则走即可）
	socksSniffing := sniffing
	if a.tunEgressIface != "" {
		socksSniffing = map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		}
	}

	inbounds := []map[string]interface{}{
		{
			"tag": "socks-in", "listen": listen, "port": a.settings.SocksPort,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": true},
			"sniffing": socksSniffing,
		},
		{
			"tag": "http-in", "listen": listen, "port": a.settings.HttpPort,
			"protocol": "http",
			"settings": map[string]interface{}{"allowTransparent": false},
			"sniffing": sniffing,
		},
	}
	// TUN 的 UDP 走独立的、不嗅探的 SOCKS 入站：Xray 1.8.24 只要开了 sniffing 就会对每个
	// UDP 会话首包跑 QUIC 嗅探器，而 SniffQUIC 在 CRYPTO 帧 offset+length 超过 2048 时
	// 越界 panic（Chrome/Edge 的 Kyber ClientHello 即可触发），整个进程崩溃。
	// TUN 下 UDP 本来就只按 IP 规则分流（destOverride 不含 quic），不嗅探不影响路由。
	if a.tunEgressIface != "" && a.tunUDPPort != 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"tag": tunUDPInboundTag, "listen": "127.0.0.1", "port": a.tunUDPPort,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": true},
		})
	}

	proxyOut, err := a.buildProxyOutboundLocked(node, a.bridgeAddr)
	if err != nil {
		return "", err
	}

	directOut := map[string]interface{}{"tag": "direct", "protocol": "freedom", "settings": map[string]interface{}{}}
	if a.tunEgressIface != "" {
		// TUN 开启：直连出站绑定物理网卡，私网/直连目标绝不被 TUN 默认路由吸回来形成回环
		directOut["streamSettings"] = map[string]interface{}{"sockopt": map[string]interface{}{"interface": a.tunEgressIface}}
	}
	outbounds := []map[string]interface{}{
		proxyOut,
		directOut,
		{"tag": "block", "protocol": "blackhole", "settings": map[string]interface{}{}},
	}

	var rules []ruleObj
	// sstap:<file> 自定义 .rules 在路由表层分流，到达 Xray 的流量本就该全部走代理，
	// 因此对它而言等同于 global。
	// 内置四种策略不再依赖路由表分流（TUN 只送默认路由进来），由下面这套规则真正生效，
	// 与系统代理路径共用同一份策略，不会出现两套引擎不一致。
	effectiveMode := a.routingMode
	if strings.HasPrefix(effectiveMode, "sstap:") {
		effectiveMode = "global"
	}
	// TUN 模式 = 全局接管：不论用户保存的策略是什么，TUN 下一律按 global（私网直连、其余走代理）。
	if a.tunEgressIface != "" {
		effectiveMode = tunPolicy
	}
	switch effectiveMode {
	case "global":
		// 局域网必须直连：否则路由器 / 打印机 / NAS / 本地开发服务器全部不可达。
		// 这条同时也是 TUN 模式的分流规则（TUN 下策略固定为 global，见上）。
		rules = append(rules,
			adsBlockRule(),
			ruleObj{Type: "field", IP: []string{"geoip:private"}, OutboundTag: "direct"},
			ruleObj{Type: "field", Network: "tcp,udp", OutboundTag: "proxy"},
		)
	case "direct":
		rules = append(rules, ruleObj{Type: "field", Network: "tcp,udp", OutboundTag: "direct"})
	case "proxy-cn":
		// 仅代理国内：geoip:cn 走代理，其余直连
		rules = append(rules,
			ruleObj{Type: "field", IP: []string{"geoip:cn"}, OutboundTag: "proxy"},
			ruleObj{Type: "field", Network: "tcp,udp", OutboundTag: "direct"},
		)
	default: // bypass-cn
		rules = append(rules,
			adsBlockRule(),
			ruleObj{Type: "field", IP: []string{"geoip:private"}, OutboundTag: "direct"},
			ruleObj{Type: "field", Domain: []string{"geosite:cn"}, OutboundTag: "direct"},
			ruleObj{Type: "field", IP: []string{"geoip:cn"}, OutboundTag: "direct"},
			ruleObj{Type: "field", Network: "tcp,udp", OutboundTag: "proxy"},
		)
	}

	dnsServers := []string{}
	for _, s := range strings.Split(a.settings.DnsServers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			dnsServers = append(dnsServers, s)
		}
	}
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1", "8.8.8.8"}
	}
	// 全局直连时必须换用国内 DNS：配置的 1.1.1.1 / 8.8.8.8 从国内直连会被污染
	// 或直接不可达，解析结果指向境外站点，于是「直连」仍表现为代理 IP。
	if effectiveMode == "direct" {
		dnsServers = []string{"223.5.5.5", "119.29.29.29"}
	}

	cfg := map[string]interface{}{
		"log":   map[string]interface{}{"loglevel": "warning"},
		"dns":   map[string]interface{}{"servers": dnsServers, "queryStrategy": "UseIP"},
		"stats": map[string]interface{}{},
		"policy": map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{"statsUserUplink": true, "statsUserDownlink": true},
			},
			"system": map[string]interface{}{
				"statsInboundUplink": true, "statsInboundDownlink": true,
				"statsOutboundUplink": true, "statsOutboundDownlink": true,
			},
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]interface{}{"domainStrategy": "AsIs", "rules": rules},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func adsBlockRule() ruleObj {
	return ruleObj{Type: "field", Domain: []string{"geosite:category-ads-all"}, OutboundTag: "block"}
}

// proxyOutboundTag 代理出站在 Xray 配置中的固定 tag。
// 路由规则按该 tag 指向出站，热切换节点时也按它定位并替换 handler，
// 因此它必须与 buildProxyOutbound 里写死的 "tag" 保持一致。
const proxyOutboundTag = "proxy"

// buildProxyOutbound 生成 Xray 的 proxy 出站。
// bridgeAddr 仅 AnyTLS 用得上：Xray 不认识 AnyTLS，只能把流量交给 AnyTLS 协议桥，
// 此时 proxy 出站退化成指向本机桥端口的 socks 出站（空串表示桥没起）。
func buildProxyOutbound(node NodeItem, muxEnabled bool, bridgeAddr string) (map[string]interface{}, error) {
	if needsAnyTLSBridge(node.Protocol) {
		if bridgeAddr == "" {
			return nil, fmt.Errorf("AnyTLS bridge is not running")
		}
		host, portStr, err := net.SplitHostPort(bridgeAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid AnyTLS bridge address: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid AnyTLS bridge port: %w", err)
		}
		// udp: true 是必须的：桥的 mixed 入站支持 UDP，
		// 缺了它 Xray 的 UDP 流量（QUIC、游戏、STUN）会在桥这一层断掉
		return map[string]interface{}{
			"tag":      "proxy",
			"protocol": "socks",
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{{"address": host, "port": port}},
				"udp":     true,
			},
		}, nil
	}

	stream := map[string]interface{}{"network": node.Network}
	switch node.Security {
	case "tls":
		tls := map[string]interface{}{
			"serverName":    firstNonEmpty(node.SNI, node.Address),
			"allowInsecure": node.Insecure, // 仅当分享链接显式要求（allowInsecure/insecure/skip-cert-verify）
		}
		if node.FP != "" {
			tls["fingerprint"] = node.FP
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	case "reality":
		reality := map[string]interface{}{
			"serverName":  firstNonEmpty(node.SNI, node.Address),
			"publicKey":   node.PBK,
			"shortId":     node.SID,
			"fingerprint": firstNonEmpty(node.FP, "chrome"),
		}
		stream["security"] = "reality"
		stream["realitySettings"] = reality
	default:
		stream["security"] = "none"
	}

	switch node.Network {
	case "ws":
		ws := map[string]interface{}{"path": firstNonEmpty(node.Path, "/")}
		if node.HostName != "" {
			ws["headers"] = map[string]interface{}{"Host": node.HostName}
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["grpcSettings"] = map[string]interface{}{"serviceName": node.ServiceName}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]interface{}{"path": firstNonEmpty(node.Path, "/"), "host": node.HostName}
	}

	var out map[string]interface{}
	switch node.Protocol {
	case "VLESS":
		user := map[string]interface{}{"id": node.UUID, "encryption": "none", "level": 0}
		if node.Flow != "" {
			user["flow"] = node.Flow
		}
		out = map[string]interface{}{
			"tag": "proxy", "protocol": "vless",
			"settings":       map[string]interface{}{"vnext": []map[string]interface{}{{"address": node.Address, "port": node.Port, "users": []map[string]interface{}{user}}}},
			"streamSettings": stream,
		}
	case "VMess":
		aid := node.AlterID
		out = map[string]interface{}{
			"tag": "proxy", "protocol": "vmess",
			"settings":       map[string]interface{}{"vnext": []map[string]interface{}{{"address": node.Address, "port": node.Port, "users": []map[string]interface{}{{"id": node.UUID, "alterId": aid, "security": "auto", "level": 0}}}}},
			"streamSettings": stream,
		}
	case "Trojan":
		out = map[string]interface{}{
			"tag": "proxy", "protocol": "trojan",
			"settings":       map[string]interface{}{"servers": []map[string]interface{}{{"address": node.Address, "port": node.Port, "password": node.UUID, "level": 0}}},
			"streamSettings": stream,
		}
	case "Shadowsocks":
		method := node.Method
		password := node.UUID
		if method == "" && strings.Contains(node.UUID, ":") {
			// 兼容旧字段格式 "method:password"
			parts := strings.SplitN(node.UUID, ":", 2)
			method, password = parts[0], parts[1]
		}
		if method == "" {
			return nil, fmt.Errorf("Shadowsocks node missing cipher method")
		}
		out = map[string]interface{}{
			"tag": "proxy", "protocol": "shadowsocks",
			"settings":       map[string]interface{}{"servers": []map[string]interface{}{{"address": node.Address, "port": node.Port, "method": method, "password": password}}},
			"streamSettings": stream,
		}
	case "HTTP", "SOCKS":
		server := map[string]interface{}{"address": node.Address, "port": node.Port}
		if node.Username != "" || node.UUID != "" {
			server["users"] = []map[string]interface{}{{"user": node.Username, "pass": node.UUID, "level": 0}}
		}
		protocol := "http"
		if node.Protocol == "SOCKS" {
			protocol = "socks"
		}
		out = map[string]interface{}{
			"tag": "proxy", "protocol": protocol,
			"settings":       map[string]interface{}{"servers": []map[string]interface{}{server}},
			"streamSettings": stream,
		}
	default:
		return nil, fmt.Errorf("Xray core does not support %s", node.Protocol)
	}

	if proxyUsesMux(node, muxEnabled) {
		out["mux"] = map[string]interface{}{"enabled": true, "concurrency": 8}
	}
	return out, nil
}

// buildProxyOutboundLocked 按当前运行状态生成 proxy 出站（调用方需持有锁）。
//
// TUN 开启时（tunEgressIface 非空）：
//   - 不开 mux：整机流量挤进 8 路复用连接会队头阻塞；
//   - streamSettings.sockopt.interface 绑定物理网卡：到节点的连接不管解析出哪个 IP
//     （CDN/多 A 记录/AAAA）都直接走物理网卡，不会被 TUN 默认路由吸回形成回环；
//   - Shadowsocks 节点地址钉成预解析 IP（与防回环 /32 一致）：Xray 的 UDP 拨号不受
//     sockopt.interface 约束，钉 IP 保证 UDP 也走 /32。SS 没有 SNI/Host，钉 IP 无副作用。
//
// AnyTLS 出站指向本机协议桥（回环），不绑网卡；桥自己已把节点钉成 /32 里的 IP。
func (a *App) buildProxyOutboundLocked(node NodeItem, bridgeAddr string) (map[string]interface{}, error) {
	tun := a.tunEgressIface != ""
	if tun && (node.Protocol == "Shadowsocks" || node.Protocol == "SOCKS") && net.ParseIP(node.Address) == nil {
		if ips := lookupNodeIPv4sCached(node.Address); len(ips) > 0 {
			node.Address = ips[0].String()
		}
	}
	out, err := buildProxyOutbound(node, a.settings.MuxEnabled && !tun, bridgeAddr)
	if err != nil || !tun || needsAnyTLSBridge(node.Protocol) {
		return out, err
	}
	stream, _ := out["streamSettings"].(map[string]interface{})
	if stream == nil {
		stream = map[string]interface{}{}
		out["streamSettings"] = stream
	}
	stream["sockopt"] = map[string]interface{}{"interface": a.tunEgressIface}
	return out, nil
}

// startCoreLocked 启动 Xray 内核（调用方需持有写锁）
func (a *App) startCoreLocked() error {
	a.stopCoreLocked()

	var node *NodeItem
	for i := range a.nodes {
		if a.nodes[i].Active {
			node = &a.nodes[i]
			break
		}
	}
	if node == nil {
		return fmt.Errorf("no node selected, cannot start core")
	}

	assetDir, err := ensureGeoAssets()
	if err != nil {
		return fmt.Errorf("failed to unpack routing data: %w", err)
	}
	os.Setenv("xray.location.asset", assetDir)

	// 端口占用预检，给出比内核原始报错更明确的提示
	preListen := "127.0.0.1"
	if a.settings.AllowLan {
		preListen = "0.0.0.0"
	}
	for _, p := range []struct {
		name string
		port int
	}{{"SOCKS5", a.settings.SocksPort}, {"HTTP", a.settings.HttpPort}} {
		addr := fmt.Sprintf("%s:%d", preListen, p.port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return &portInUseError{name: p.name, port: p.port}
		}
		ln.Close()
	}

	// Xray 不支持 AnyTLS：这类节点先起 AnyTLS 协议桥，
	// 再把它的本地 SOCKS 端口当作 Xray 的 proxy 出站
	if needsAnyTLSBridge(node.Protocol) {
		bridge, err := startAnyTLSBridge(*node)
		if err != nil {
			return fmt.Errorf("failed to start AnyTLS bridge: %w", err)
		}
		a.bridge = bridge
		a.bridgeAddr = bridge.addr
	}

	coreCfg, err := a.buildCoreConfigLocked(*node)
	if err != nil {
		a.stopBridgeLocked()
		return err
	}
	// 用可热替换的 router，运行中切换分流策略无需重启内核（见 routerswap.go）
	if err := useSwappableRouter(coreCfg); err != nil {
		a.stopBridgeLocked()
		return fmt.Errorf("failed to prepare routing: %w", err)
	}
	inst, err := xcore.New(coreCfg)
	if err != nil {
		a.stopBridgeLocked()
		return fmt.Errorf("failed to create core instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		a.stopBridgeLocked()
		if looksLikePortInUse(err) {
			// 预检与真正监听之间端口被别的程序抢占（或被系统保留）
			return fmt.Errorf("%w (%v)", errPortInUse, err)
		}
		return fmt.Errorf("failed to start core: %w", err)
	}
	a.xrayInst = inst
	a.statsInst.set(inst)
	a.coreNodeID = node.ID
	a.coreErr, a.corePortErr = "", false
	a.addLogInternal("info", fmt.Sprintf("Xray-core %s started | SOCKS5 127.0.0.1:%d / HTTP 127.0.0.1:%d | node: %s",
		xrayCoreVersion(), a.settings.SocksPort, a.settings.HttpPort, node.Name))
	return nil
}

// buildCoreConfigLocked 生成并构建 node 对应的完整内核配置（调用方需持有锁）。
func (a *App) buildCoreConfigLocked(node NodeItem) (*xcore.Config, error) {
	cfgJSON, err := a.buildCoreConfigJSON(node)
	if err != nil {
		return nil, err
	}
	pbCfg, err := serial.DecodeJSONConfig(bytes.NewReader([]byte(cfgJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse core config: %w", err)
	}
	coreCfg, err := pbCfg.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build core config: %w", err)
	}
	return coreCfg, nil
}

// stopCoreLocked 停止内核（调用方需持有写锁）
func (a *App) stopCoreLocked() {
	if a.xrayInst != nil {
		a.xrayInst.Close()
		// 关实例不会断开已接入的连接，残留隧道会继续按旧配置出站，这里一并切断。
		if n := outboundConnTracker.Retire(a.xrayInst); n > 0 {
			a.addLogInternal("info", fmt.Sprintf("Closed %d connection(s) left on the stopped core", n))
		}
		a.xrayInst = nil
	}
	a.statsInst.set(nil)
	a.coreNodeID = ""
	a.stopBridgeLocked()
}

// stopBridgeLocked 停掉 AnyTLS 协议桥（调用方需持有写锁；无桥时为空操作）。
func (a *App) stopBridgeLocked() {
	if a.bridge != nil {
		a.bridge.Stop()
		a.bridge = nil
	}
	a.bridgeAddr = ""
}

// realDelayTestConfig 生成测速用临时 Xray 实例的配置：SOCKS 入站（port）→ 该节点 proxy 出站。
//
// egressIface 非空（TUN 正在接管整机流量）时，proxy 出站 sockopt.interface 绑定物理网卡，
// 与主内核同一做法：到被测节点的连接直接走物理网卡，不会被 TUN 默认路由吸进隧道、
// 套着当前节点出去（那样测出的是「当前节点 + 被测节点」的叠加延迟，还占用当前节点流量）。
// 测速只走 TCP（SOCKS 入站关 UDP），sockopt.interface 对 TCP 拨号生效。
func realDelayTestConfig(node NodeItem, port int, egressIface, bridgeAddr string) (map[string]interface{}, error) {
	proxyOut, err := buildProxyOutbound(node, false, bridgeAddr)
	if err != nil {
		return nil, err
	}
	// AnyTLS 出站指向本机协议桥（回环），不绑网卡；桥自己拨号时已钉 /32 里的 IP
	if egressIface != "" && !needsAnyTLSBridge(node.Protocol) {
		stream, _ := proxyOut["streamSettings"].(map[string]interface{})
		if stream == nil {
			stream = map[string]interface{}{}
			proxyOut["streamSettings"] = stream
		}
		stream["sockopt"] = map[string]interface{}{"interface": egressIface}
	}
	return map[string]interface{}{
		"inbounds": []map[string]interface{}{{
			"tag": "test-in", "listen": "127.0.0.1", "port": port,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": false},
		}},
		"outbounds": []map[string]interface{}{proxyOut},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []map[string]interface{}{
				{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
			},
		},
	}, nil
}

// testNodeRealDelay 真连接测速：为该节点临时启动一个独立 Xray 实例（随机端口 SOCKS 入站），
// 通过该节点的真实代理链路请求测速 URL（完整 DNS+TCP+TLS+HTTP），返回毫秒；失败返回 -2。
// 临时实例与主内核完全独立，不改动现网出站、系统代理或 TUN 路由。
// egressIface 见 realDelayTestConfig（TUN 开启时传物理网卡名，否则传空）。
func testNodeRealDelay(node NodeItem, egressIface string) int {
	// 与 v2rayN 默认的真连接延迟测速地址一致，保证数值可比
	const testURL = "https://www.google.com/generate_204"

	// AnyTLS 走进程内协议桥：临时起一个桥，Xray 出站指向它。
	// 每次测速独立起停，桥不与常驻内核共享（并发测速时各占各的端口）。
	bridgeAddr := ""
	if needsAnyTLSBridge(node.Protocol) {
		bridge, err := startAnyTLSBridge(node)
		if err != nil {
			return -2
		}
		defer bridge.Stop()
		bridgeAddr = bridge.addr
	}

	// 找一个空闲端口给临时实例的 SOCKS 入站
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return -2
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg, err := realDelayTestConfig(node, port, egressIface, bridgeAddr)
	if err != nil {
		return -2
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return -2
	}
	pbCfg, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return -2
	}
	coreCfg, err := pbCfg.Build()
	if err != nil {
		return -2
	}
	inst, err := xcore.New(coreCfg)
	if err != nil {
		return -2
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return -2
	}
	defer inst.Close()

	// 等待本地入站就绪（最多 3 秒）
	localAddr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", localAddr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			return -2
		}
		time.Sleep(100 * time.Millisecond)
	}

	proxyURL, _ := url.Parse("socks5://" + localAddr)
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSHandshakeTimeout: 6 * time.Second,
		},
	}
	// v2rayN 同款口径（GetRealPingTime）：同一客户端连测两次取较小值。
	// 第一次要建立完整链路（SOCKS 握手 + 节点 TCP/TLS + 目标站 TLS），
	// 第二次复用 keep-alive 连接只剩 HTTP 往返 —— 取 min 后的结果是
	// 「热连接」往返时间，与 v2rayN 显示的真连接延迟可比。
	// 测两次中只要有一次成功即算节点可用，两次都失败才返回 -2。
	best := -1
	for i := 0; i < 2; i++ {
		start := time.Now()
		resp, err := client.Get(testURL)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode < 500 {
				ms := int(time.Since(start).Milliseconds())
				if ms <= 0 {
					ms = 1
				}
				if best < 0 || ms < best {
					best = ms
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if best < 0 {
		return -2
	}
	return best
}

// ------------------------- 节点热切换 -------------------------

// errHotSwapUnavailable 表示无法热切换（内核未运行、拿不到出站管理器，或替换失败且
// 旧出站也放不回去），调用方应回退到整体重启内核。
//
// 其余错误都意味着「新节点本身有问题，现网出站保持原样」：整体重启只会以同样的
// 原因失败，还会白白拆掉正在工作的内核，所以调用方不应再重启。
var errHotSwapUnavailable = errors.New("hot swap unavailable")

// errNodeRejected 表示新节点在拆除任何现网状态之前就被拒绝（如配置构建失败），
// TUN 隧道与内核出站均保持原样，调用方无需软停 TUN。
var errNodeRejected = errors.New("node rejected before switching")

// preparedOutbound 是已构建好、尚未装入内核的 proxy 出站。
//
// 拆成 prepare/commit 两步，是为了让 TUN 硬切换可以在拆隧道之前先验证新节点：
// 新节点配置有问题时直接返回，隧道与现网出站都不受影响。
type preparedOutbound struct {
	node    NodeItem
	handler *xcore.OutboundHandlerConfig
	// bridge 新节点为 AnyTLS 时预先拉起的协议桥。提交成功后移交给 App，
	// 未提交（失败或放弃）时由 discard 关闭，避免残留 协议桥。
	bridge *anyTLSBridge
}

func (p *preparedOutbound) discard() {
	if p != nil && p.bridge != nil {
		p.bridge.Stop()
		p.bridge = nil
	}
}

// prepareProxyOutboundLocked 为 node 构建新的 proxy 出站（调用方需持有写锁）。
// 不触碰正在运行的内核；失败时现网出站保持原样。
func (a *App) prepareProxyOutboundLocked(node NodeItem) (*preparedOutbound, error) {
	if a.xrayInst == nil {
		return nil, errHotSwapUnavailable
	}
	p := &preparedOutbound{node: node}

	// AnyTLS：Xray 无此出站，新节点要先起自己的协议桥，proxy 出站指向它。
	// 旧桥（如有）此时仍在服务旧节点，等新出站就位后才停。
	bridgeAddr := ""
	if needsAnyTLSBridge(node.Protocol) {
		bridge, err := startAnyTLSBridge(node)
		if err != nil {
			return nil, fmt.Errorf("failed to start AnyTLS bridge: %w", err)
		}
		p.bridge = bridge
		bridgeAddr = bridge.addr
	}

	proxyOut, err := a.buildProxyOutboundLocked(node, bridgeAddr)
	if err != nil {
		p.discard()
		return nil, err
	}
	raw, err := json.Marshal(map[string]interface{}{
		"outbounds": []interface{}{proxyOut},
	})
	if err != nil {
		p.discard()
		return nil, err
	}
	pbCfg, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		p.discard()
		return nil, fmt.Errorf("failed to parse outbound config: %w", err)
	}
	builtCfg, err := pbCfg.Build()
	if err != nil {
		p.discard()
		return nil, fmt.Errorf("failed to build outbound config: %w", err)
	}
	if len(builtCfg.Outbound) == 0 {
		p.discard()
		return nil, errHotSwapUnavailable
	}
	p.handler = builtCfg.Outbound[0]
	return p, nil
}

// commitProxyOutboundLocked 把 prepare 好的出站换进正在运行的内核（调用方需持有写锁）。
// 无论成败，p 都被消费：失败时其协议桥会被关闭。
func (a *App) commitProxyOutboundLocked(p *preparedOutbound) error {
	inst := a.xrayInst
	if inst == nil {
		p.discard()
		return errHotSwapUnavailable
	}
	mgr, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		p.discard()
		return errHotSwapUnavailable
	}

	// 1) 摘除旧 handler。Xray 的 AddHandler 遇到同名 tag 会直接报错，
	//    所以必须先摘再加；RemoveHandler 只从表里删除、不会关闭 handler，
	//    因此先取出引用，等新 handler 就位后再由我们关闭。
	//    （proxy 若是默认出站，摘除会把 defaultHandler 置空，AddHandler 时自动补上。）
	old := mgr.GetHandler(proxyOutboundTag)
	if err := mgr.RemoveHandler(context.Background(), proxyOutboundTag); err != nil {
		p.discard()
		return fmt.Errorf("failed to detach current outbound: %w", err)
	}

	// 推进出站连接的代际：此刻起开始的拨号都算新代际。旧 handler 已摘除，
	// 分发器不会再把新请求交给它，因此在此之前开始的拨号都属于旧节点。
	cut := outboundConnTracker.Advance()

	// 2) 装入新 handler。失败则把旧 handler 放回去，避免代理出站凭空消失
	//    （此时 tag 是空的，放回不会冲突）。
	if err := xcore.AddOutboundHandler(inst, p.handler); err != nil {
		p.discard()
		if old != nil {
			if reAddErr := mgr.AddHandler(context.Background(), old); reAddErr == nil {
				return fmt.Errorf("failed to apply new outbound (previous node restored): %w", err)
			}
		}
		// 回滚也失败：代理出站已不可用，交给调用方整体重启内核兜底。
		return fmt.Errorf("%w: failed to apply new outbound and could not restore the previous one: %v",
			errHotSwapUnavailable, err)
	}

	// 3) 关闭旧 handler，释放其 mux 连接（RemoveHandler 不负责这件事）。
	//    非 mux 的存量连接各自持有到旧节点的底层连接，关 handler 切不断它们，
	//    所以再按代际关掉旧节点上的全部出站连接（见 conntrack.go）：
	//    客户端的 keep-alive 连接随之断开，重连后即走新节点，出口 IP 立刻改变。
	if old != nil {
		common.Close(old)
	}
	if n := outboundConnTracker.CloseBefore(inst, cut); n > 0 {
		a.addLogInternal("info", fmt.Sprintf("Closed %d connection(s) still using the previous node", n))
	}
	// 4) 旧节点若是 AnyTLS，现在才停它的桥（会切断旧节点上的全部连接），
	//    再把新节点的桥（如有）移交给 App 管理。
	a.stopBridgeLocked()
	if p.bridge != nil {
		a.bridge = p.bridge
		a.bridgeAddr = p.bridge.addr
		p.bridge = nil
	}
	return nil
}

// hotSwapProxyOutboundLocked 在不重启内核的前提下，把 proxy 出站换成新节点
// （调用方需持有写锁）。
//
// 整体重启内核会连带销毁 SOCKS5/HTTP 入站监听，切换期间浏览器与 TUN 转发都会
// 短暂被拒连；入站流量计数器也随实例一起销毁。换 handler 只影响代理出站本身：
// 入站监听与 direct 出站不动，统计计数器按同名 tag 复用（GetOrRegisterCounter）。
func (a *App) hotSwapProxyOutboundLocked(node NodeItem) error {
	p, err := a.prepareProxyOutboundLocked(node)
	if err != nil {
		return err
	}
	return a.commitProxyOutboundLocked(p)
}

// ------------------------- 分流策略热切换 -------------------------

// proxyUsesMux 与 buildProxyOutbound 的判断保持一致：该节点的 proxy 出站是否启用 mux。
// 带 flow（XTLS Vision）的 VLESS 绝不叠 mux：Vision 要直接拼接内层 TLS，套 mux 后
// 服务端会拒绝/断开连接。
func proxyUsesMux(node NodeItem, muxEnabled bool) bool {
	if node.Flow != "" {
		return false
	}
	return muxEnabled && (node.Protocol == "VLESS" || node.Protocol == "VMess" || node.Protocol == "Trojan")
}

// applyRoutingLocked 按当前 a.routingMode 就地替换运行中内核的路由规则（调用方需持有写锁）。
// 返回 errHotSwapUnavailable（可能被包装）时调用方应回退为整体重启内核。
//
// 与 v2rayN 一致：只影响之后新建的连接，已建立的连接保持原出口不切断
// （例如直连下开始的下载，切到全局后继续直连下完）。
//
// 仅 DNS 配置（直连模式换国内 DNS）不随之替换：系统代理路径下 Xray 内置 DNS 没有使用者
// （路由 domainStrategy=AsIs、freedom 与传输层均不经它解析），TUN 运行时本函数不会被调用。
func (a *App) applyRoutingLocked() error {
	inst := a.xrayInst
	sr := swappableRouterOf(inst)
	if sr == nil {
		return errHotSwapUnavailable
	}
	var node *NodeItem
	for i := range a.nodes {
		if a.nodes[i].Active {
			node = &a.nodes[i]
			break
		}
	}
	if node == nil || node.ID != a.coreNodeID {
		return errHotSwapUnavailable
	}
	coreCfg, err := a.buildCoreConfigLocked(*node)
	if err != nil {
		return fmt.Errorf("%w: %v", errHotSwapUnavailable, err)
	}
	rc, err := routerConfigOf(coreCfg)
	if err != nil || rc == nil {
		return fmt.Errorf("%w: no routing config (%v)", errHotSwapUnavailable, err)
	}
	if err := sr.Reload(rc); err != nil {
		return fmt.Errorf("%w: reload routing: %v", errHotSwapUnavailable, err)
	}
	return nil
}
