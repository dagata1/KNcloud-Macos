//go:build e2elive

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func fetchIP(c *http.Client) string {
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "http://ip-api.com/line?fields=query,country"} {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return strings.TrimSpace(strings.ReplaceAll(string(b), "\n", " ")) + " (" + u + ")"
		}
	}
	return "FAIL"
}

func proxyClient(port int, keepAlive bool) *http.Client {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: !keepAlive}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0600)
}

func TestLiveProxy(t *testing.T) {
	real := filepath.Join(os.Getenv("APPDATA"), "KNcloud")
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "KNcloud")
	os.MkdirAll(dst, 0700)
	for _, f := range []string{"config.json", "geoip.dat", "geosite.dat", "geosite-cn.srs", "sing-box.exe"} {
		copyFile(filepath.Join(real, f), filepath.Join(dst, f))
	}
	t.Setenv("APPDATA", tmp)

	direct := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 15 * time.Second}
	t.Logf("DIRECT (machine, no app proxy): %s", fetchIP(direct))

	a := NewApp()
	a.mu.Lock()
	a.settings.SocksPort = 21080
	a.settings.HttpPort = 21081
	a.routingMode = "global"
	a.systemProxy = false // never touch the real Windows proxy
	a.mu.Unlock()

	nodes := a.GetNodes()
	t.Logf("nodes loaded: %d, logged in: %v", len(nodes), a.GetAccount().LoggedIn)
	// 切换路线：日本 -> 新加坡 -> 日本 -> 新加坡（xh.ktno.cc Shadowsocks 节点），
	// 每一跳出口 IP 都不同，便于确认 keep-alive 客户端跟随切换。
	byName := func(kw string) (NodeItem, bool) {
		for _, n := range nodes {
			if strings.Contains(n.Name, kw) && !strings.Contains(strings.ToUpper(n.Name), "V6") {
				return n, true
			}
		}
		return NodeItem{}, false
	}
	var picks []NodeItem
	jp, okJP := byName("日本")
	sg, okSG := byName("新加坡")
	if okJP && okSG {
		picks = []NodeItem{jp, sg, jp, sg}
	}
	for _, n := range nodes {
		t.Logf("  node: [%s] %s (%s:%d)", n.Protocol, n.Name, n.Address, n.Port)
	}
	if len(picks) < 2 {
		t.Fatalf("need 日本 and 新加坡 nodes, have %d picks", len(picks))
	}
	if _, err := a.SelectNode(picks[0].ID); err != nil {
		t.Fatalf("select first: %v", err)
	}
	if ok, err := a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("start core: %v", err)
	}
	defer a.ToggleCore(false)
	time.Sleep(time.Second)

	ka := proxyClient(21081, true)
	t.Logf("NODE1 [%s] %s: %s", picks[0].Protocol, picks[0].Name, fetchIP(proxyClient(21081, false)))
	t.Logf("NODE1 keep-alive client: %s", fetchIP(ka))

	for _, n := range picks[1:] {
		start := time.Now()
		_, err := a.SelectNode(n.ID)
		t.Logf("SelectNode [%s] %s (%s) took %v err=%v coreRunning=%v", n.Protocol, n.Name, n.Address, time.Since(start), err, a.GetCoreStatus().Running)
		time.Sleep(500 * time.Millisecond)
		want := nodeExitIP[nodeKey(n.Name)]
		fresh := extractIP(fetchIP(proxyClient(21081, false)))
		old := extractIP(fetchIP(ka))
		t.Logf("  new conn IP: %s / old keep-alive client IP: %s (want %s)", fresh, old, want)
		if want != "" && (fresh != want || old != want) {
			t.Errorf("SelectNode %s: new=%s keep-alive=%s, want %s", n.Name, fresh, old, want)
		}
	}

	// rollback: bogus node
	bad := NodeItem{ID: "e2e-bad", Name: "bad", Protocol: "bogus", Address: "1.2.3.4", Port: 1}
	a.mu.Lock()
	a.nodes = append(a.nodes, bad)
	a.mu.Unlock()
	_, err := a.SelectNode(bad.ID)
	t.Logf("SelectNode bogus err=%v; IP after: %s", err, fetchIP(proxyClient(21081, false)))
	for _, n := range a.GetNodes() {
		if n.Active {
			t.Logf("  active after rollback: %s", n.Name)
		}
	}

	a.mu.Lock()
	a.savePersisted()
	a.mu.Unlock()
	b, _ := os.ReadFile(filepath.Join(dst, "config.json"))
	s := string(b)
	t.Logf("saved config: has accountToken=%v, has subscriptionUrls=%v, plaintext http sub url present=%v",
		strings.Contains(s, "\"accountToken\""), strings.Contains(s, "\"subscriptionUrls\""), strings.Contains(s, "api/v1/client/subscribe"))
}

func TestLiveFreshPerNode(t *testing.T) {
	real := filepath.Join(os.Getenv("APPDATA"), "KNcloud")
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "KNcloud")
	os.MkdirAll(dst, 0700)
	for _, f := range []string{"config.json", "geoip.dat", "geosite.dat", "geosite-cn.srs", "sing-box.exe"} {
		copyFile(filepath.Join(real, f), filepath.Join(dst, f))
	}
	t.Setenv("APPDATA", tmp)
	a := NewApp()
	a.mu.Lock()
	a.settings.SocksPort = 21080
	a.settings.HttpPort = 21081
	a.routingMode = "global"
	a.systemProxy = false
	a.mu.Unlock()
	for _, n := range a.GetNodes() {
		a.ToggleCore(false)
		a.SelectNode(n.ID)
		_, err := a.ToggleCore(true)
		time.Sleep(300 * time.Millisecond)
		t.Logf("FRESH [%s] %s (%s) err=%v: %s", n.Protocol, n.Name, n.Address, err, fetchIP(proxyClient(21081, false)))
	}
	a.ToggleCore(false)
}

const machineDirectIP = "36.133.83.215"

var nodeExitIP = map[string]string{"日本": "54.178.104.134", "新加坡": "47.128.251.122"}

func nodeKey(name string) string {
	for k := range nodeExitIP {
		if strings.Contains(name, k) {
			return k
		}
	}
	return ""
}

var ipRe = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

func extractIP(s string) string {
	if m := ipRe.FindString(s); m != "" {
		return m
	}
	return "FAIL"
}

// getIP 依次尝试 urls，返回第一个成功响应里的 IPv4。plainKA 时给请求带上
// Proxy-Connection: keep-alive（浏览器的做法），让 Xray HTTP 入站在同一条客户端连接上
// 继续处理后续明文请求。
func getIP(c *http.Client, urls []string, plainKA bool) string {
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "curl/8.0")
		if plainKA {
			req.Header.Set("Proxy-Connection", "keep-alive")
		}
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			if ip := extractIP(string(b)); ip != "FAIL" {
				return ip
			}
		}
	}
	return "FAIL"
}

var (
	foreignEcho      = []string{"https://ifconfig.me/ip", "https://api.ipify.org"}
	mainlandEcho     = []string{"https://ip.3322.net", "https://myip.ipip.net"}
	foreignEchoHTTP  = []string{"http://ifconfig.me/ip"}
	mainlandEchoHTTP = []string{"http://ip.3322.net"}
)

func setupLiveApp(t *testing.T) (*App, string) {
	real := filepath.Join(os.Getenv("APPDATA"), "KNcloud")
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "KNcloud")
	os.MkdirAll(dst, 0700)
	for _, f := range []string{"config.json", "geoip.dat", "geosite.dat", "geosite-cn.srs", "sing-box.exe"} {
		copyFile(filepath.Join(real, f), filepath.Join(dst, f))
	}
	t.Setenv("APPDATA", tmp)
	a := NewApp()
	a.mu.Lock()
	a.settings.SocksPort = 21080
	a.settings.HttpPort = 21081
	a.systemProxy = false // never touch the real Windows proxy
	a.mu.Unlock()
	return a, dst
}

// TestLiveRoutingModes 内核运行中切换 全局 / 直连 / 绕过大陆，新连接与存量 keep-alive
// 连接都必须立即按新策略出站；策略落盘，换节点后策略保持。
func TestLiveRoutingModes(t *testing.T) {
	a, dst := setupLiveApp(t)
	a.mu.Lock()
	a.routingMode = "global"
	a.mu.Unlock()
	var jp, sg NodeItem
	for _, n := range a.GetNodes() {
		if strings.Contains(strings.ToUpper(n.Name), "V6") {
			continue
		}
		if jp.ID == "" && strings.Contains(n.Name, "日本") {
			jp = n
		}
		if sg.ID == "" && strings.Contains(n.Name, "新加坡") {
			sg = n
		}
	}
	if jp.ID == "" || sg.ID == "" {
		t.Fatal("need 日本 and 新加坡 nodes")
	}
	if _, err := a.SelectNode(jp.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("start core: %v", err)
	}
	defer a.ToggleCore(false)
	time.Sleep(time.Second)

	ka := proxyClient(21081, true)
	kaPlain := proxyClient(21081, true)
	expect := func(mode, node string) (mainland, foreign string) {
		switch mode {
		case "global":
			return node, node
		case "direct":
			return machineDirectIP, machineDirectIP
		default:
			return machineDirectIP, node
		}
	}
	check := func(label, mode, node string) {
		time.Sleep(300 * time.Millisecond)
		wm, wf := expect(mode, node)
		nm := getIP(proxyClient(21081, false), mainlandEcho, false)
		nf := getIP(proxyClient(21081, false), foreignEcho, false)
		km := getIP(ka, mainlandEcho, false)
		kf := getIP(ka, foreignEcho, false)
		pm := getIP(kaPlain, mainlandEchoHTTP, true)
		pf := getIP(kaPlain, foreignEchoHTTP, true)
		t.Logf("ROW | %s | mode=%s | mainland new=%s ka=%s plainKA=%s | foreign new=%s ka=%s plainKA=%s | want mainland=%s foreign=%s",
			label, a.GetCoreStatus().RoutingMode, nm, km, pm, nf, kf, pf, wm, wf)
		if nm != wm || km != wm || nf != wf || kf != wf {
			t.Errorf("%s: mainland new=%s ka=%s foreign new=%s ka=%s, want mainland=%s foreign=%s", label, nm, km, nf, kf, wm, wf)
		}
		if pm != wm || pf != wf {
			t.Errorf("%s (plain HTTP keep-alive): mainland=%s foreign=%s, want %s / %s", label, pm, pf, wm, wf)
		}
	}
	jpIP := nodeExitIP["日本"]
	check("start global", "global", jpIP)
	seq := []string{"direct", "bypass-cn", "global", "bypass-cn", "direct", "global"}
	prev := "global"
	for _, m := range seq {
		start := time.Now()
		ok, err := a.SetRoutingMode(m)
		t.Logf("SetRoutingMode %s -> %s took %v ok=%v err=%v running=%v", prev, m, time.Since(start), ok, err, a.GetCoreStatus().Running)
		if !ok || err != nil {
			t.Fatalf("SetRoutingMode(%s): %v", m, err)
		}
		check(prev+" -> "+m, m, jpIP)
		prev = m
	}

	// 策略落盘 + 换节点后保持
	if _, err := a.SetRoutingMode("bypass-cn"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SelectNode(sg.ID); err != nil {
		t.Fatalf("select sg: %v", err)
	}
	if m := a.GetCoreStatus().RoutingMode; m != "bypass-cn" {
		t.Errorf("mode after SelectNode = %s, want bypass-cn", m)
	}
	check("bypass-cn + SelectNode 新加坡", "bypass-cn", nodeExitIP["新加坡"])
	b, _ := os.ReadFile(filepath.Join(dst, "config.json"))
	if !strings.Contains(string(b), `"routingMode":"bypass-cn"`) && !strings.Contains(string(b), `"routingMode": "bypass-cn"`) {
		t.Errorf("config.json does not persist routingMode bypass-cn")
	}
	if _, err := a.SetRoutingMode("direct"); err != nil {
		t.Fatal(err)
	}
	b2 := NewApp() // 重新加载落盘配置（不启动内核）
	b2.mu.RLock()
	got := b2.routingMode
	b2.mu.RUnlock()
	t.Logf("reloaded routingMode=%s", got)
	if got != "direct" {
		t.Errorf("reloaded routingMode=%s, want direct", got)
	}
}
