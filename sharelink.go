package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// errUnsupportedProtocol 可识别但本版本不支持的协议（如 AnyTLS）：批量导入/订阅时跳过并记日志。
var errUnsupportedProtocol = errors.New("unsupported protocol")

// ParseShareLink 将单条分享链接解析为节点；无法识别时返回错误。
func ParseShareLink(link string) (NodeItem, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return NodeItem{}, fmt.Errorf("empty link")
	}
	lower := strings.ToLower(link)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMessLink(link)
	case strings.HasPrefix(lower, "vless://"):
		return parseUserHostLink(link, "VLESS")
	case strings.HasPrefix(lower, "trojan://"):
		return parseUserHostLink(link, "Trojan")
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocksLink(link)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return parseUserHostLink(link, "Hysteria2")
	case strings.HasPrefix(lower, "anytls://"):
		// AnyTLS 需要 sing-box 协议桥（Xray 没有该出站），已随 sing-box 一并移除
		return NodeItem{}, fmt.Errorf("%w: AnyTLS is not supported in this version", errUnsupportedProtocol)
	default:
		return NodeItem{}, fmt.Errorf("unrecognized protocol")
	}
}

func decodeB64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.StdEncoding.DecodeString(s)
}

func parseVMessLink(link string) (NodeItem, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	raw = strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
	data, err := decodeB64Flexible(raw)
	if err != nil {
		return NodeItem{}, fmt.Errorf("vmess base64 decode failed: %w", err)
	}
	var j map[string]string
	if err := json.Unmarshal(data, &j); err != nil {
		return NodeItem{}, fmt.Errorf("vmess JSON parse failed: %w", err)
	}
	port, _ := strconv.Atoi(j["port"])
	aid, _ := strconv.Atoi(j["aid"])
	security := strings.ToLower(j["tls"])
	if security == "true" {
		security = "tls"
	}
	if security != "reality" {
		if security == "tls" || security == "none" || security == "" {
			// keep
		} else {
			security = "tls"
		}
	}
	network := j["net"]
	if network == "" {
		network = "tcp"
	}
	return NodeItem{
		Name:        firstNonEmpty(j["ps"], j["add"]),
		Protocol:    "VMess",
		Address:     j["add"],
		Port:        port,
		UUID:        j["id"],
		AlterID:     aid,
		Security:    security,
		Network:     network,
		SNI:         firstNonEmpty(j["sni"], j["host"]),
		FP:          j["fp"],
		Path:        j["path"],
		HostName:    j["host"],
		ServiceName: j["path"],
		Delay:       -1,
	}, nil
}

// parseUserHostLink 处理 vless:// trojan:// hysteria2:// 这类 URI 形式的链接
func parseUserHostLink(link, proto string) (NodeItem, error) {
	u, err := url.Parse(link)
	if err != nil {
		return NodeItem{}, fmt.Errorf("link parse failed: %w", err)
	}
	if u.Host == "" {
		return NodeItem{}, fmt.Errorf("missing server address")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return NodeItem{}, fmt.Errorf("invalid port")
	}
	q := u.Query()
	name, _ := url.QueryUnescape(u.Fragment)

	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	security := strings.ToLower(q.Get("security"))
	if proto == "Trojan" && security == "" {
		security = "tls"
	}
	if proto == "Hysteria2" {
		security = "tls"
		network = "udp"
	}
	methodPass := ""
	if proto == "Shadowsocks" {
		methodPass = u.User.Username()
	}
	return NodeItem{
		Name:        firstNonEmpty(name, u.Hostname()),
		Protocol:    proto,
		Address:     u.Hostname(),
		Port:        port,
		UUID:        firstNonEmpty(u.User.Username(), q.Get("auth")),
		Method:      methodPass,
		Security:    security,
		Network:     network,
		Flow:        q.Get("flow"),
		SNI:         firstNonEmpty(q.Get("sni"), q.Get("peer"), u.Hostname()),
		FP:          q.Get("fp"),
		PBK:         q.Get("pbk"),
		SID:         q.Get("sid"),
		Path:        q.Get("path"),
		HostName:    q.Get("host"),
		ServiceName: q.Get("serviceName"),
		Insecure:    parseBoolParam(firstNonEmpty(q.Get("insecure"), q.Get("allowInsecure"))),
		Delay:       -1,
	}, nil
}

// parseBoolParam 分享链接里的布尔参数：1/true/yes/on 都算真，空值算假。
func parseBoolParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func parseShadowsocksLink(link string) (NodeItem, error) {
	rest := strings.TrimPrefix(link, "ss://")
	fragment := ""
	if idx := strings.Index(rest, "#"); idx >= 0 {
		fragment, _ = url.QueryUnescape(rest[idx+1:])
		rest = rest[:idx]
	}
	// SIP002: ss://base64(method:password)@host:port
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo := rest[:at]
		hostpart := rest[at+1:]
		if q := strings.Index(hostpart, "?"); q >= 0 {
			hostpart = hostpart[:q]
		}
		decoded, err := decodeB64Flexible(userinfo)
		if err != nil {
			// 明文 method:password
			decoded = []byte(userinfo)
		}
		up, err := url.Parse("ss://" + string(decoded) + "@" + hostpart)
		if err != nil {
			return NodeItem{}, fmt.Errorf("ss link parse failed: %w", err)
		}
		port, err := strconv.Atoi(up.Port())
		if err != nil {
			return NodeItem{}, fmt.Errorf("invalid port for ss link")
		}
		method := up.User.Username()
		pass, _ := up.User.Password()
		if method == "" {
			return NodeItem{}, fmt.Errorf("ss link missing cipher method")
		}
		return NodeItem{
			Name:     firstNonEmpty(fragment, up.Hostname()),
			Protocol: "Shadowsocks",
			Address:  up.Hostname(),
			Port:     port,
			Method:   method,
			UUID:     pass,
			Security: "none",
			Network:  "tcp",
			Delay:    -1,
		}, nil
	}
	// 旧版: ss://base64(method:password@host:port)
	if q := strings.Index(rest, "?"); q >= 0 {
		rest = rest[:q]
	}
	decoded, err := decodeB64Flexible(rest)
	if err != nil {
		return NodeItem{}, fmt.Errorf("ss base64 decode failed: %w", err)
	}
	up, err := url.Parse("ss://" + string(decoded))
	if err != nil {
		return NodeItem{}, fmt.Errorf("ss link parse failed: %w", err)
	}
	port, err := strconv.Atoi(up.Port())
	if err != nil {
		return NodeItem{}, fmt.Errorf("invalid port for ss link")
	}
	pass, _ := up.User.Password()
	return NodeItem{
		Name:     firstNonEmpty(fragment, up.Hostname()),
		Protocol: "Shadowsocks",
		Address:  up.Hostname(),
		Port:     port,
		Method:   up.User.Username(),
		UUID:     pass,
		Security: "none",
		Network:  "tcp",
		Delay:    -1,
	}, nil
}

// ParseShareLinks 批量解析（支持整段 base64 订阅内容或按行分隔的链接）
func ParseShareLinks(content string) []NodeItem {
	nodes, _ := ParseShareLinksReport(content)
	return nodes
}

// ParseShareLinksReport 同 ParseShareLinks，另返回因协议不受支持而跳过的条数（按协议名计）。
func ParseShareLinksReport(content string) ([]NodeItem, map[string]int) {
	skipped := map[string]int{}
	content = strings.TrimSpace(content)
	var lines []string
	if !strings.Contains(content, "://") {
		if data, err := decodeB64Flexible(content); err == nil && strings.Contains(string(data), "://") {
			content = string(data)
		}
	}
	for _, l := range strings.FieldsFunc(content, func(r rune) bool { return r == '\n' || r == '\r' }) {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}

	var nodes []NodeItem
	for _, l := range lines {
		n, err := ParseShareLink(l)
		if err != nil {
			if errors.Is(err, errUnsupportedProtocol) {
				skipped[strings.ToLower(strings.SplitN(l, "://", 2)[0])]++
			}
			continue
		}
		// 过滤机场订阅里的“流量信息 / 套餐到期”等伪装成节点的条目
		if isInfoPseudoNode(n) {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, skipped
}

// skippedLinksLog 把跳过统计写成一行日志文案；没有跳过返回空串。
func skippedLinksLog(skipped map[string]int) string {
	if len(skipped) == 0 {
		return ""
	}
	var parts []string
	for proto, n := range skipped {
		parts = append(parts, fmt.Sprintf("%d %s", n, proto))
	}
	sort.Strings(parts)
	return "Skipped unsupported link(s): " + strings.Join(parts, ", ") + " (AnyTLS is not supported in this version)"
}

// BuildShareLink 将节点转换回标准分享链接（ParseShareLink 的逆操作），用于复制到剪贴板。
func BuildShareLink(n NodeItem) (string, error) {
	switch n.Protocol {
	case "Shadowsocks":
		if n.Method == "" || n.UUID == "" {
			return "", fmt.Errorf("Shadowsocks node missing cipher method or password")
		}
		// SIP002: ss://base64url(method:password)@host:port#name
		user := base64.RawURLEncoding.EncodeToString([]byte(n.Method + ":" + n.UUID))
		return fmt.Sprintf("ss://%s@%s:%d#%s", user, n.Address, n.Port, url.QueryEscape(n.Name)), nil
	case "VMess":
		tls := n.Security
		if tls != "tls" && tls != "reality" {
			tls = ""
		}
		j := map[string]string{
			"v": "2", "ps": n.Name, "add": n.Address, "port": strconv.Itoa(n.Port),
			"id": n.UUID, "aid": strconv.Itoa(n.AlterID), "scy": "auto",
			"net": firstNonEmpty(n.Network, "tcp"), "tls": tls,
			"sni": n.SNI, "host": n.HostName, "path": n.Path, "fp": n.FP,
		}
		data, err := json.Marshal(j)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.RawURLEncoding.EncodeToString(data), nil
	case "VLESS", "Trojan", "Hysteria2":
		q := url.Values{}
		if n.Security != "" && n.Security != "none" {
			q.Set("security", n.Security)
		}
		if n.Insecure {
			q.Set("insecure", "1")
			q.Set("allowInsecure", "1")
		}
		if n.Network != "" && n.Network != "tcp" {
			q.Set("type", n.Network)
		}
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.FP != "" {
			q.Set("fp", n.FP)
		}
		if n.Flow != "" {
			q.Set("flow", n.Flow)
		}
		if n.PBK != "" {
			q.Set("pbk", n.PBK)
		}
		if n.SID != "" {
			q.Set("sid", n.SID)
		}
		if n.Path != "" {
			q.Set("path", n.Path)
		}
		if n.HostName != "" {
			q.Set("host", n.HostName)
		}
		if n.ServiceName != "" {
			q.Set("serviceName", n.ServiceName)
		}
		scheme := strings.ToLower(n.Protocol)
		u := url.URL{
			Scheme: scheme,
			User:   url.User(n.UUID),
			Host:   fmt.Sprintf("%s:%d", n.Address, n.Port),
		}
		if enc := q.Encode(); enc != "" {
			u.RawQuery = enc
		}
		u.Fragment = n.Name
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", n.Protocol)
	}
}

func isInfoPseudoNode(n NodeItem) bool {
	host := strings.ToLower(n.Address)
	if host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" || host == "localhost" {
		return true
	}
	name := n.Name
	for _, kw := range []string{"流量", "到期", "过期", "剩余", "官网", "套餐", "重置", "发布", "群", "官网"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
