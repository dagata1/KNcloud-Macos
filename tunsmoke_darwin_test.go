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
