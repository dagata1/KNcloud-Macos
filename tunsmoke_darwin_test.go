//go:build darwin && tunsmoke

package main

// tunsmoke_darwin_test.go —— macOS TUN 端到端冒烟（CI：go test -tags tunsmoke，需要免密 sudo）。
//
// 走与生产完全相同的路径：
//   1. 普通用户进程经 sudo -n 拉起特权助手（本测试二进制的 --tun-helper 模式），
//      校验 LOCAL_PEERCRED 与 SCM_RIGHTS 传递 utun 描述符；
//   2. gVisor 转发器挂在 utun 上，出口是内嵌 Xray 的 SOCKS 入站（freedom 出站 redirect 到本地测试服务）；
//   3. 助手写路由：198.51.100.0/24 进 utun、198.18.0.2/32（DNS 劫持）进 utun、2000::/3 进 utun、
//      203.0.113.9/32 经物理网关；
//   4. curl 风格的 HTTP 请求（TCP）与 UDP 回显都穿过 utun→gVisor→SOCKS→Xray→本地服务；
//      DNS 查询经 198.18.0.2 中继到物理网卡上的公共 DNS；系统 DNS 改写后用 dig 走系统解析器验证；
//   5. 撤路由、还原 DNS，确认系统恢复原状。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "--tun-helper" {
		os.Exit(runTunHelper(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func startRedirectXray(t *testing.T, socksPort, targetPort int) func() {
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{map[string]any{
			"tag": "direct", "protocol": "freedom",
			"settings": map[string]any{"redirect": fmt.Sprintf("127.0.0.1:%d", targetPort)},
		}},
	}
	data, _ := json.Marshal(cfg)
	pb, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("xray config: %v", err)
	}
	cc, err := pb.Build()
	if err != nil {
		t.Fatalf("xray build: %v", err)
	}
	inst, err := xcore.New(cc)
	if err != nil {
		t.Fatalf("xray new: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("xray start: %v", err)
	}
	return func() { inst.Close() }
}

func TestDarwinTunSmoke(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root: helper will be launched directly")
	} else if exec.Command("/usr/bin/sudo", "-n", "/usr/bin/true").Run() != nil {
		t.Skip("needs root or passwordless sudo")
	}
	t0 := time.Now()
	step := func(format string, args ...any) {
		t.Logf("[%6.2fs] "+format, append([]any{time.Since(t0).Seconds()}, args...)...)
	}

	// --- 本地目标服务：同一端口上的 HTTP(TCP) 与 UDP 回显 ---
	port := pickFreeLoopbackPort()
	if port == 0 {
		t.Fatal("no free port")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const body = "hello-through-utun"
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body+" host="+r.Host)
	}))
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(append([]byte("echo:"), buf[:n]...), a)
		}
	}()

	socksPort := pickFreeLoopbackPort()
	stopXray := startRedirectXray(t, socksPort, port)
	defer stopXray()
	step("xray SOCKS on %d, redirect target 127.0.0.1:%d", socksPort, port)

	// --- 特权助手（生产路径：sudo -n / osascript 拉起本程序 --tun-helper） ---
	dir, err := os.MkdirTemp("/tmp", "kn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tunHelper.sockOverride = filepath.Join(dir, "h.sock")
	if err := prepareTunPrivileges(); err != nil {
		t.Fatalf("launch helper: %v", err)
	}
	defer func() {
		tunHelper.do(helperReq{Op: "cleanup"})
		tunHelper.call(helperReq{Op: "quit"})
		tunHelper.close()
		if b, err := os.ReadFile(filepath.Join(dir, "tunhelper.log")); err == nil {
			t.Logf("helper log:\n%s", b)
		}
	}()
	if !isElevated() {
		t.Fatal("helper should be connected")
	}
	step("helper connected")

	// --- utun + gVisor 转发器 ---
	phys, ok := physHopFor(net.ParseIP("8.8.8.8"), 0)
	if !ok {
		t.Fatal("no physical default route")
	}
	dev := currentTunDevice()
	idx, err := dev.Open()
	if err != nil {
		t.Fatalf("open utun: %v", err)
	}
	defer knUtun.closeDevice()
	step("utun %s index %d mtu %d; physical if %d gw %s", dev.Name(), idx, dev.LinkMTU(), phys.IfIndex, u32ToIP(phys.NextHop))
	if out, err := exec.Command("/sbin/ifconfig", dev.Name()).CombinedOutput(); err == nil {
		t.Logf("ifconfig:\n%s", out)
	}
	link := dev.NewLink()
	fwd, err := newTapForwarder(link, tapForwarderConfig{
		SocksAddr:   fmt.Sprintf("127.0.0.1:%d", socksPort),
		DNSAddr:     tunDnsAddr,
		DNSUpstream: "8.8.8.8:53",
		BindIdx:     phys.IfIndex,
	})
	if err != nil {
		t.Fatalf("forwarder: %v", err)
	}
	defer func() {
		dev.StopLink(link, time.Second)
		fwd.stop(2 * time.Second)
	}()

	// --- 路由（经助手；与 tunctl 相同的 routeEntry → darwinRouteOps） ---
	ops := defaultRouteOps()
	st := newTunRouteState()
	gw := ipToU32(net.ParseIP(tunGateway))
	mk := func(c string, nh, ifIdx uint32, kind string) routeEntry {
		_, n, _ := net.ParseCIDR(c)
		return newRoute(*n, nh, ifIdx, 5, kind)
	}
	desired := []routeEntry{
		mk("203.0.113.9/32", phys.NextHop, phys.IfIndex, "host"),
		mk(tunDnsAddr+"/32", gw, idx, "split"),
		mk("198.51.100.0/24", gw, idx, "split"),
	}
	if _, _, err := st.sync(ops, desired); err != nil {
		t.Fatalf("route sync: %v", err)
	}
	if err := addTunIPv6Route(idx); err != nil {
		t.Logf("IPv6 2000::/3 route: %v", err)
	} else {
		step("IPv6 2000::/3 -> %s installed", dev.Name())
	}
	out, _ := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, dev.Name()) || strings.HasPrefix(l, "203.0.113.9") || strings.HasPrefix(l, "default") {
			t.Logf("route: %s", l)
		}
	}
	h, ok := physHopFor(net.ParseIP("198.51.100.7"), idx)
	if !ok || h.IfIndex == idx {
		t.Fatalf("physHopFor must skip the utun even when it carries the more specific route: %+v %v", h, ok)
	}
	step("routes installed (%d)", st.count(""))

	// --- TCP：HTTP 穿过 utun ---
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	var got string
	for i := 0; i < 10; i++ {
		resp, err := client.Get("http://198.51.100.7/smoke")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			got = string(b)
			break
		}
		t.Logf("http attempt %d: %v", i+1, err)
		time.Sleep(300 * time.Millisecond)
	}
	if !strings.HasPrefix(got, body) {
		t.Fatalf("HTTP through utun failed, body=%q", got)
	}
	step("TCP OK: %q", got)

	// curl 本身（系统工具，确认不是 Go 进程的特殊路径）
	if out, err := exec.Command("/usr/bin/curl", "-sS", "--max-time", "10", "http://198.51.100.8/curl").CombinedOutput(); err != nil || !strings.HasPrefix(string(out), body) {
		t.Fatalf("curl through utun: %v %q", err, out)
	} else {
		step("curl OK: %q", out)
	}

	// --- UDP：SOCKS UDP ASSOCIATE 路径 ---
	uconn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()
	var ugot string
	for i := 0; i < 10 && ugot == ""; i++ {
		uconn.Write([]byte("ping"))
		uconn.SetReadDeadline(time.Now().Add(1 * time.Second))
		b := make([]byte, 256)
		if n, err := uconn.Read(b); err == nil {
			ugot = string(b[:n])
		}
	}
	if ugot != "echo:ping" {
		t.Fatalf("UDP through utun failed, got %q", ugot)
	}
	step("UDP OK: %q", ugot)

	// --- DNS：发往 198.18.0.2 的查询由中继经物理网卡转给 8.8.8.8 ---
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", tunDnsAddr+":53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ips, err := r.LookupHost(ctx, "dns.google")
	cancel()
	if err != nil || len(ips) == 0 {
		t.Fatalf("DNS via %s relay failed: %v", tunDnsAddr, err)
	}
	step("DNS relay OK: dns.google -> %v", ips)

	// --- 系统 DNS 劫持（networksetup）并用系统解析器验证，然后还原 ---
	svcs, _ := networkServices()
	before := map[string][]string{}
	for _, s := range svcs {
		before[s] = getServiceDNS(s)
	}
	if err := setTapAdapterDNS(idx); err != nil {
		t.Fatalf("set system DNS: %v", err)
	}
	if !adapterHasDns(idx, tunDnsAddr) {
		t.Fatal("helper reports DNS not hijacked")
	}
	if len(svcs) > 0 {
		if d := getServiceDNS(svcs[0]); len(d) == 0 || d[0] != tunDnsAddr {
			t.Fatalf("service %q DNS = %v", svcs[0], d)
		}
	}
	time.Sleep(time.Second)
	if out, err := exec.Command("/usr/bin/dig", "+time=3", "+tries=2", "+short", "example.com").CombinedOutput(); err == nil && len(bytes.TrimSpace(out)) > 0 {
		step("system resolver (dig) via hijacked DNS OK: %s", strings.Join(strings.Fields(string(out)), " "))
	} else {
		sc, _ := exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput()
		t.Logf("dig via system DNS failed (%v): %s\nscutil --dns (head): %.1500s", err, out, sc)
	}
	clearTapAdapterDNS(idx)
	for _, s := range svcs {
		if a, b := strings.Join(getServiceDNS(s), ","), strings.Join(before[s], ","); a != b {
			t.Fatalf("DNS of %q not restored: %s != %s", s, a, b)
		}
	}
	step("system DNS restored")

	// --- 撤路由 ---
	removed, failed := st.clear(ops)
	removeTunIPv6RouteFast(idx)
	if failed > 0 {
		t.Fatalf("%d routes failed to delete", failed)
	}
	out, _ = exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").CombinedOutput()
	if strings.Contains(string(out), "198.51.100") || strings.Contains(string(out), "203.0.113.9") {
		t.Fatalf("routes left behind:\n%s", out)
	}
	step("removed %d routes, routing table clean", removed)
	stats := fmt.Sprintf("tcp=%d udp=%d dns=%d", fwd.tcpActive.Load(), fwd.udpActive.Load(), fwd.dnsActive.Load())
	step("forwarder active flows at end: %s", stats)
	fmt.Println("TUN-SMOKE PASS")
}

// TestDarwinAppTunE2E 整个 App 的 TUN 开关（SimpleConnect，与界面/菜单同一入口）：
// 节点是跑在本机物理网卡地址上的 Xray SOCKS 服务端（其 freedom 出站绑定物理网卡，不进 TUN）。
// 开 TUN 后不设任何代理直接 curl https://example.com：系统 DNS 被劫持到 198.18.0.2、
// 默认路由进 utun → gVisor → 主内核 SOCKS 入站 → 节点 → 互联网；关 TUN 后路由/DNS 全部还原。
func TestDarwinAppTunE2E(t *testing.T) {
	if os.Getenv("KNCLOUD_APP_TUN_E2E") != "1" {
		t.Skip("set KNCLOUD_APP_TUN_E2E=1 (takes over the whole machine's traffic for a few seconds)")
	}
	if os.Geteuid() != 0 && exec.Command("/usr/bin/sudo", "-n", "/usr/bin/true").Run() != nil {
		t.Skip("needs root or passwordless sudo")
	}
	t0 := time.Now()
	step := func(format string, args ...any) {
		t.Logf("[%6.2fs] "+format, append([]any{time.Since(t0).Seconds()}, args...)...)
	}
	cfgDir := t.TempDir()
	t.Setenv("APPDATA", cfgDir)
	dir, err := os.MkdirTemp("/tmp", "kn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tunHelper.close()
	tunHelper.sockOverride = filepath.Join(dir, "h.sock")
	knUtun.closeDevice()

	phys, ok := physHopFor(net.ParseIP("8.8.8.8"), 0)
	if !ok {
		t.Fatal("no physical default route")
	}
	ifc, err := net.InterfaceByIndex(int(phys.IfIndex))
	if err != nil {
		t.Fatal(err)
	}
	var physIP string
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			physIP = n.IP.String()
			break
		}
	}
	if physIP == "" {
		t.Fatalf("no IPv4 on %s", ifc.Name)
	}
	srvPort := pickFreeLoopbackPort()
	srv := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "srv-in", "listen": physIP, "port": srvPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": physIP},
		}},
		"outbounds": []any{map[string]any{
			"tag": "srv-out", "protocol": "freedom",
			"streamSettings": map[string]any{"sockopt": map[string]any{"interface": ifc.Name}},
		}},
	}
	data, _ := json.Marshal(srv)
	pb, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	cc, err := pb.Build()
	if err != nil {
		t.Fatal(err)
	}
	srvInst, err := xcore.New(cc)
	if err != nil {
		t.Fatal(err)
	}
	if err := srvInst.Start(); err != nil {
		t.Fatal(err)
	}
	defer srvInst.Close()
	step("node = SOCKS server on %s:%d (egress bound to %s)", physIP, srvPort, ifc.Name)

	a := &App{
		routingMode: "bypass-cn",
		settings: AppSettings{
			SocksPort: pickFreeLoopbackPort(), HttpPort: pickFreeLoopbackPort(),
			DnsServers: "1.1.1.1", MuxEnabled: false,
		},
		nodes:        []NodeItem{{ID: "n1", Name: "lan-socks", Protocol: "SOCKS", Address: physIP, Port: srvPort, Network: "tcp", Active: true}},
		activeNodeID: "n1",
	}
	a.mu.Lock()
	if err := a.startCoreLocked(); err != nil {
		a.mu.Unlock()
		t.Fatalf("start core: %v", err)
	}
	a.coreRunning = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.tunSoftStopLocked()
		a.stopCoreLocked()
		a.coreRunning = false
		a.mu.Unlock()
		tunHelper.do(helperReq{Op: "cleanup"})
		tunHelper.call(helperReq{Op: "quit"})
		tunHelper.close()
		knUtun.closeDevice()
		for _, l := range a.GetLogs() {
			t.Logf("app log: [%s] %s", l.Level, l.Message)
		}
	}()

	svcs, _ := networkServices()
	before := map[string][]string{}
	for _, s := range svcs {
		before[s] = getServiceDNS(s)
	}

	on, err := a.SimpleConnect(true)
	if err != nil || !on {
		t.Fatalf("SimpleConnect(true): on=%v err=%v", on, err)
	}
	step("TUN on via SimpleConnect (%d routes, utun index %d)", a.tunRt.count(""), a.tunIfaceIdx)
	out, _ := exec.Command("/sbin/route", "-n", "get", "1.0.0.1").CombinedOutput()
	if !strings.Contains(string(out), "interface: utun") {
		t.Fatalf("default traffic is not routed into utun:\n%s", out)
	}
	if len(svcs) > 0 {
		if d := getServiceDNS(svcs[0]); len(d) == 0 || d[0] != tunDnsAddr {
			t.Fatalf("system DNS not hijacked: %v", d)
		}
	}
	// 诊断：分别验证 DNS 中继（Go 解析器直连 198.18.0.2）、resolv.conf 路径（dig）、
	// 系统解析器（mDNSResponder：dscacheutil），以及中继上游本身是否可达
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", tunDnsAddr+":53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	ips, rerr := r.LookupHost(ctx, "example.com")
	cancel()
	step("relay lookup via %s: %v %v", tunDnsAddr, ips, rerr)
	diag := func(tag string) {
		f := a.tap
		if f == nil {
			step("%s: forwarder is nil", tag)
			return
		}
		step("%s: dnsFlows=%d dnsDialErr=%d dnsReplies=%d tcp=%d udp=%d | %s | bindIdx=%d upstream=%s",
			tag, f.dnsFlows.Load(), f.dnsDialErr.Load(), f.dnsReplies.Load(), f.tcpActive.Load(), f.udpActive.Load(),
			utunCounters(), f.cfg.BindIdx, f.cfg.DNSUpstream)
	}
	diag("after relay lookup")
	// 上游直连（与中继同样绑定物理网卡）：区分「中继没收到」与「上游不通」
	br := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Control: bindToIfaceControl(a.tunPhys.IfIndex)}
		return d.DialContext(ctx, "udp", "223.5.5.5:53")
	}}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 6*time.Second)
	bips, berr := br.LookupHost(ctx2, "example.com")
	cancel2()
	step("bound(if %d) direct lookup via 223.5.5.5: %v %v", a.tunPhys.IfIndex, bips, berr)
	for _, c := range [][]string{
		{"/usr/sbin/netstat", "-rn", "-f", "inet"},
		{"/sbin/route", "-n", "get", tunDnsAddr},
		{"/sbin/route", "-n", "get", "223.5.5.5"},
		{"/sbin/route", "-n", "get", tunGateway},
		{"/sbin/ifconfig", currentTunDevice().Name()},
	} {
		o, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if len(o) > 4000 {
			o = o[:4000]
		}
		step("%s: err=%v\n%s", strings.Join(c, " "), err, o)
	}
	// TCP 路径单独验证（跳过 DNS）
	if len(bips) > 0 {
		o, err := exec.Command("/usr/bin/curl", "-sS", "--noproxy", "*", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15",
			"--resolve", "example.com:443:"+bips[0], "https://example.com/").CombinedOutput()
		step("curl --resolve example.com:443:%s through TUN: %v %s", bips[0], err, o)
	}
	diag("after tcp probe")
	for _, c := range [][]string{
		{"/usr/bin/dig", "+time=3", "+tries=1", "+short", "example.com"},
		{"/usr/bin/dscacheutil", "-q", "host", "-a", "name", "example.com"},
		{"/usr/sbin/scutil", "--dns"},
	} {
		o, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if len(o) > 1500 {
			o = o[:1500]
		}
		step("%s: err=%v\n%s", strings.Join(c, " "), err, o)
	}
	var code string
	for i := 0; i < 2 && code != "200"; i++ {
		o, err := exec.Command("/usr/bin/curl", "-sS", "--noproxy", "*", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "https://example.com/").CombinedOutput()
		code = strings.TrimSpace(string(o))
		if err != nil {
			t.Logf("curl attempt %d: %v %s", i+1, err, o)
		}
	}
	if code != "200" {
		t.Fatalf("curl https://example.com through app TUN: %q", code)
	}
	step("curl https://example.com through TUN -> HTTP %s (tcp flows seen: %d)", code, a.tap.tcpActive.Load())

	if on, err := a.SimpleConnect(false); err != nil || on {
		t.Fatalf("SimpleConnect(false): on=%v err=%v", on, err)
	}
	out, _ = exec.Command("/sbin/route", "-n", "get", "1.0.0.1").CombinedOutput()
	if strings.Contains(string(out), "interface: utun") {
		t.Fatalf("utun still carries default traffic after TUN off:\n%s", out)
	}
	for _, s := range svcs {
		if a, b := strings.Join(getServiceDNS(s), ","), strings.Join(before[s], ","); a != b {
			t.Fatalf("DNS of %q not restored: %s != %s", s, a, b)
		}
	}
	step("TUN off: routes and DNS restored")
	fmt.Println("APP-TUN-E2E PASS")
}
