//go:build darwin

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBestDarwinRoute(t *testing.T) {
	cidr := func(s string) (uint32, int) {
		_, n, _ := net.ParseCIDR(s)
		ones, _ := n.Mask.Size()
		return ipToU32(n.IP), ones
	}
	mk := func(c, gw string, idx uint32, scoped bool) darwinRoute {
		d, b := cidr(c)
		return darwinRoute{Dest: d, Bits: b, NextHop: ipToU32(net.ParseIP(gw)), IfIndex: idx, Scoped: scoped}
	}
	noLo := func(idx uint32) bool { return idx == 1 }
	rows := []darwinRoute{
		mk("0.0.0.0/0", "192.168.1.1", 4, false),
		mk("0.0.0.0/0", "10.0.0.1", 7, true), // 其它接口的 IFSCOPE 默认路由
		mk("0.0.0.0/1", "172.19.0.1", 20, false),
		mk("128.0.0.0/1", "172.19.0.1", 20, false),
		mk("127.0.0.0/8", "127.0.0.1", 1, false),
		mk("192.168.1.0/24", "", 4, false),
	}
	r, ok := bestDarwinRoute(rows, net.ParseIP("8.8.8.8"), 20, noLo)
	if !ok || r.IfIndex != 4 || u32ToIP(r.NextHop).String() != "192.168.1.1" {
		t.Fatalf("8.8.8.8 should leave via en(4)/192.168.1.1 when utun(20) is excluded, got %+v ok=%v", r, ok)
	}
	r, ok = bestDarwinRoute(rows, net.ParseIP("8.8.8.8"), 0, noLo)
	if !ok || r.IfIndex != 20 {
		t.Fatalf("without exclusion the /1 TUN route must win, got %+v", r)
	}
	r, ok = bestDarwinRoute(rows, net.ParseIP("192.168.1.50"), 20, noLo)
	if !ok || r.IfIndex != 4 || r.NextHop != 0 {
		t.Fatalf("on-link LAN host should be direct on if 4, got %+v", r)
	}
	if _, ok := bestDarwinRoute(rows[4:5], net.ParseIP("8.8.8.8"), 0, noLo); ok {
		t.Fatal("loopback-only table must not yield a route")
	}
}

// TestDarwinPhysHopLive 读真实内核路由表：CI 机器一定有默认出口。
func TestDarwinPhysHopLive(t *testing.T) {
	rows, err := darwinIPv4Routes()
	if err != nil {
		t.Fatalf("read routing table: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("empty routing table")
	}
	h, ok := physHopFor(net.ParseIP("8.8.8.8"), 0)
	if !ok {
		t.Skip("no IPv4 default route on this machine")
	}
	ifc, err := net.InterfaceByIndex(int(h.IfIndex))
	if err != nil {
		t.Fatalf("hop interface %d: %v", h.IfIndex, err)
	}
	t.Logf("physical hop for 8.8.8.8: if=%s(%d) gw=%s", ifc.Name, h.IfIndex, u32ToIP(h.NextHop))
	// 与 route get 对照（只比接口名）
	out, err := exec.Command("/sbin/route", "-n", "get", "8.8.8.8").CombinedOutput()
	if err == nil && strings.Contains(string(out), "interface:") && !strings.Contains(string(out), "interface: "+ifc.Name) {
		t.Logf("note: route get disagrees (may be a VPN/utun):\n%s", out)
	}
}

func TestHelperFrameWithFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	toConn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "sp")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := toConn(fds[0]), toConn(fds[1])
	defer a.Close()
	defer b.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	go writeHelperFrame(a, helperResp{OK: true, Name: "utun99", Index: 42, MTU: 9000}, int(w.Fd()))
	var resp helperResp
	got, err := readHelperFrame(b, &resp)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !resp.OK || resp.Name != "utun99" || resp.Index != 42 || len(got) != 1 {
		t.Fatalf("bad frame %+v fds=%v", resp, got)
	}
	// 传过来的描述符可用：往里写，从原管道读端读出
	pf := os.NewFile(uintptr(got[0]), "passed")
	defer pf.Close()
	if _, err := pf.Write([]byte("hi")); err != nil {
		t.Fatalf("write passed fd: %v", err)
	}
	buf := make([]byte, 2)
	r.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.Read(buf); err != nil || string(buf) != "hi" {
		t.Fatalf("passed fd not connected to pipe: %q %v", buf, err)
	}
	// 普通帧（不带描述符）
	go writeHelperFrame(a, helperReq{Op: "route_add", Dst: "1.2.3.0/24", Gateway: "192.168.1.1"}, -1)
	var req helperReq
	if got, err := readHelperFrame(b, &req); err != nil || len(got) != 0 || req.Dst != "1.2.3.0/24" {
		t.Fatalf("plain frame: %+v %v %v", req, got, err)
	}
}

func TestValidateHelperRoute(t *testing.T) {
	ok := []helperReq{
		{Op: "route_add", Dst: "0.0.0.0/1", Iface: "utun5"},
		{Op: "route_add", Dst: "1.2.3.4/32", Gateway: "192.168.1.1"},
		{Op: "route_add", Dst: "2000::/3", Iface: "utun5", V6: true},
	}
	for _, r := range ok {
		if _, err := validateHelperRoute(r); err != nil {
			t.Errorf("%+v rejected: %v", r, err)
		}
	}
	bad := []helperReq{
		{Dst: "1.2.3.4", Gateway: "1.1.1.1"},
		{Dst: "1.2.3.0/24"},
		{Dst: "1.2.3.0/24", Iface: "en0; rm -rf /"},
		{Dst: "1.2.3.0/24", Gateway: "not-an-ip"},
		{Dst: "2000::/3", Iface: "utun1"}, // 族不匹配
	}
	for _, r := range bad {
		if _, err := validateHelperRoute(r); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if got := strings.Join(routeCmdArgs("add", helperRoute{Dst: "0.0.0.0/0", Gateway: "192.168.1.1", Scope: "en0"}), " "); got != "-n add -net 0.0.0.0/0 192.168.1.1 -ifscope en0" {
		t.Fatalf("scoped default args: %s", got)
	}
	args := routeCmdArgs("add", helperRoute{Dst: "0.0.0.0/1", Iface: "utun3"})
	if strings.Join(args, " ") != "-n add -net 0.0.0.0/1 -interface utun3" {
		t.Fatalf("route args: %v", args)
	}
}

func TestQuoting(t *testing.T) {
	if got := shellQuote("/Applications/K N'c.app"); got != `'/Applications/K N'\''c.app'` {
		t.Fatalf("shellQuote: %s", got)
	}
	if got := appleScriptString(`a "b" \c`); got != `"a \"b\" \\c"` {
		t.Fatalf("appleScriptString: %s", got)
	}
}

func TestLaunchAgentPlistIsValid(t *testing.T) {
	content, err := launchAgentPlist()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "a.plist")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", p).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v\n%s\n%s", err, out, content)
	}
}

// TestSystemProxyRoundTrip 真改系统代理再还原（仅 CI 打开：KNCLOUD_SYSPROXY_TEST=1）。
func TestSystemProxyRoundTrip(t *testing.T) {
	if os.Getenv("KNCLOUD_SYSPROXY_TEST") != "1" {
		t.Skip("set KNCLOUD_SYSPROXY_TEST=1 to modify the real system proxy")
	}
	svcs, err := proxyServices()
	if err != nil || len(svcs) == 0 {
		t.Fatalf("network services: %v %v", svcs, err)
	}
	t.Logf("services: %q", svcs)
	sysProxySocksPort.Store(10808)
	if err := setSystemProxy(true, "127.0.0.1:10809"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !getSystemProxy() {
		t.Fatal("system proxy should read back as enabled")
	}
	on, srv := webProxyOf(svcs[0])
	if !on || srv != "127.0.0.1:10809" {
		t.Fatalf("service %q web proxy = %v %q", svcs[0], on, srv)
	}
	restoreSystemProxyIfOurs()
	if on, _ := webProxyOf(svcs[0]); on {
		t.Fatal("restoreSystemProxyIfOurs did not disable our proxy")
	}
}
