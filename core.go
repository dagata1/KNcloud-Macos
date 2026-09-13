package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/features/stats"

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
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

//go:embed geo/geoip.dat geo/geosite.dat
var geoAssets embed.FS

// ensureGeoAssets 将内置的 geoip/geosite 数据释放到用户配置目录，返回资产目录。
func ensureGeoAssets() (string, error) {
	dir, err := appConfigDir()
	if err != nil {
		return "", err
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		dst := filepath.Join(dir, name)
		if st, err := os.Stat(dst); err == nil && st.Size() > 1024 {
			continue
		}
		src, err := geoAssets.Open("geo/" + name)
		if err != nil {
			return "", err
		}
		out, err := os.Create(dst)
		if err != nil {
			src.Close()
			return "", err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			src.Close()
			return "", err
		}
		out.Close()
		src.Close()
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
	case "VLESS", "VMess", "Trojan", "Shadowsocks":
	default:
		return "", fmt.Errorf("Xray core does not support %s (supported: VLESS/VMess/Trojan/Shadowsocks)", node.Protocol)
	}

	listen := "127.0.0.1"
	if a.settings.AllowLan {
		listen = "0.0.0.0"
	}
	sniffing := map[string]interface{}{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
	}

	inbounds := []map[string]interface{}{
		{
			"tag": "socks-in", "listen": listen, "port": a.settings.SocksPort,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": true},
			"sniffing": sniffing,
		},
		{
			"tag": "http-in", "listen": listen, "port": a.settings.HttpPort,
			"protocol": "http",
			"settings": map[string]interface{}{"allowTransparent": false},
			"sniffing": sniffing,
		},
	}

	proxyOut, err := buildProxyOutbound(node, a.settings.MuxEnabled)
	if err != nil {
		return "", err
	}

	outbounds := []map[string]interface{}{
		proxyOut,
		{"tag": "direct", "protocol": "freedom", "settings": map[string]interface{}{}},
		{"tag": "block", "protocol": "blackhole", "settings": map[string]interface{}{}},
	}

	var rules []ruleObj
	switch a.routingMode {
	case "global":
		rules = append(rules, adsBlockRule(), ruleObj{Type: "field", Network: "tcp,udp", OutboundTag: "proxy"})
	case "direct":
		rules = append(rules, ruleObj{Type: "field", Network: "tcp,udp", OutboundTag: "direct"})
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

	cfg := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"dns": map[string]interface{}{"servers": dnsServers, "queryStrategy": "UseIP"},
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

func buildProxyOutbound(node NodeItem, muxEnabled bool) (map[string]interface{}, error) {
	stream := map[string]interface{}{"network": node.Network}
	switch node.Security {
	case "tls":
		tls := map[string]interface{}{
			"serverName":    firstNonEmpty(node.SNI, node.Address),
			"allowInsecure": false,
		}
		if node.FP != "" {
			tls["fingerprint"] = node.FP
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	case "reality":
		reality := map[string]interface{}{
			"serverName": firstNonEmpty(node.SNI, node.Address),
			"publicKey":  node.PBK,
			"shortId":    node.SID,
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
	default:
		return nil, fmt.Errorf("Xray core does not support %s", node.Protocol)
	}

	if muxEnabled && (node.Protocol == "VLESS" || node.Protocol == "VMess" || node.Protocol == "Trojan") {
		out["mux"] = map[string]interface{}{"enabled": true, "concurrency": 8}
	}
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
			return fmt.Errorf("%s port %d is already in use, please change the port in Preferences", p.name, p.port)
		}
		ln.Close()
	}

	cfgJSON, err := a.buildCoreConfigJSON(*node)
	if err != nil {
		return err
	}

	pbCfg, err := serial.DecodeJSONConfig(bytes.NewReader([]byte(cfgJSON)))
	if err != nil {
		return fmt.Errorf("failed to parse core config: %w", err)
	}
	coreCfg, err := pbCfg.Build()
	if err != nil {
		return fmt.Errorf("failed to build core config: %w", err)
	}
	inst, err := xcore.New(coreCfg)
	if err != nil {
		return fmt.Errorf("failed to create core instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return fmt.Errorf("failed to start core: %w", err)
	}
	a.xrayInst = inst
	a.addLogInternal("info", fmt.Sprintf("Xray-core %s started | SOCKS5 127.0.0.1:%d / HTTP 127.0.0.1:%d | node: %s",
		xrayCoreVersion(), a.settings.SocksPort, a.settings.HttpPort, node.Name))
	return nil
}

// stopCoreLocked 停止内核（调用方需持有写锁）
func (a *App) stopCoreLocked() {
	if a.xrayInst != nil {
		a.xrayInst.Close()
		a.xrayInst = nil
	}
}

// coreTrafficSample 读取内核流量计数器（字节），用于实时速率显示
func (a *App) coreTrafficSample() (up, down int64, ok bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.xrayInst == nil {
		return 0, 0, false
	}
	feat := a.xrayInst.GetFeature(stats.ManagerType())
	if feat == nil {
		return 0, 0, false
	}
	mgr, ok2 := feat.(stats.Manager)
	if !ok2 {
		return 0, 0, false
	}
	for _, tag := range []string{"socks-in", "http-in"} {
		if c := mgr.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", tag)); c != nil {
			up += c.Value()
		}
		if c := mgr.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", tag)); c != nil {
			down += c.Value()
		}
	}
	return up, down, true
}

// testNodeRealDelay 真连接测速：为该节点临时启动一个独立 Xray 实例（随机端口 SOCKS 入站），
// 通过该节点的真实代理链路请求测速 URL（完整 DNS+TCP+TLS+HTTP），返回毫秒；失败返回 -2。
func testNodeRealDelay(node NodeItem) int {
	// 与 v2rayN 默认的真连接延迟测速地址一致，保证数值可比
	const testURL = "https://www.google.com/generate_204"

	proxyOut, err := buildProxyOutbound(node, false)
	if err != nil {
		return -2
	}

	// 找一个空闲端口给临时实例的 SOCKS 入站
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return -2
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := map[string]interface{}{
		"inbounds": []map[string]interface{}{{
			"tag": "test-in", "listen": "127.0.0.1", "port": port,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": false},
		}},
		"outbounds": []map[string]interface{}{
			proxyOut,
			{"tag": "direct", "protocol": "freedom", "settings": map[string]interface{}{}},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []map[string]interface{}{
				{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
			},
		},
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
