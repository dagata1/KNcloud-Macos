package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRangeToCIDRs(t *testing.T) {
	// 简单用例逐一验证
	check := func(s, e uint64, want []string) {
		t.Helper()
		got := rangeToCIDRs(s, e)
		var gs []string
		for _, c := range got {
			gs = append(gs, c.String())
		}
		if strings.Join(gs, ",") != strings.Join(want, ",") {
			t.Fatalf("rangeToCIDRs(%d,%d) = %v, want %v", s, e, gs, want)
		}
	}
	check(1<<24, (1<<24)+255, []string{"1.0.0.0/24"})
	check(0, 0, []string{"0.0.0.0/32"})
	check((4<<24)+1, (4<<24)+5, []string{"4.0.0.1/32", "4.0.0.2/31", "4.0.0.4/31"})
	check(0, (1<<32)-1, []string{"0.0.0.0/0"})
}

func TestComputeBypassRoutes(t *testing.T) {
	routes := computeBypassRoutes()
	if len(routes) < 1000 {
		t.Fatalf("bypass routes too few: %d", len(routes))
	}

	// 1) 不与大陆 CIDR、保留网段重叠
	for _, r := range routes {
		if r.IP.To4() == nil {
			t.Fatalf("non-IPv4 route: %s", r.String())
		}
		start := uint64(ipToU32(r.IP))
		ones, _ := r.Mask.Size()
		end := start + (uint64(1) << (32 - ones)) - 1
		// 与每个大陆/保留区间做精确重叠检查
		for _, line := range append(strings.Split(cnRoutesTxt, "\n"), reservedCIDRs...) {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(line))
			if err != nil {
				continue
			}
			cs := uint64(ipToU32(ipnet.IP))
			cones, _ := ipnet.Mask.Size()
			ce := cs + (uint64(1) << (32 - cones)) - 1
			if start <= ce && cs <= end {
				t.Fatalf("route %s overlaps %s", r.String(), ipnet.String())
			}
		}
	}

	// 2) 覆盖性抽查：已知海外 IP 必须落在某条路由内，国内 IP 必须不在
	mustContain := []string{"8.8.8.8", "1.1.1.1", "104.16.132.229"}
	for _, s := range mustContain {
		ip := net.ParseIP(s)
		u := uint64(ipToU32(ip))
		ok := false
		for _, r := range routes {
			ones, _ := r.Mask.Size()
			rs := uint64(ipToU32(r.IP))
			re := rs + (uint64(1) << (32 - ones)) - 1
			if u >= rs && u <= re {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("expected bypass route covering %s", s)
		}
	}
	mustNotContain := []string{"119.29.29.29", "223.5.5.5", "211.136.17.107", "114.114.114.114", "192.168.1.1", "10.0.0.1"}
	for _, s := range mustNotContain {
		ip := net.ParseIP(s)
		u := uint64(ipToU32(ip))
		for _, r := range routes {
			ones, _ := r.Mask.Size()
			rs := uint64(ipToU32(r.IP))
			re := rs + (uint64(1) << (32 - ones)) - 1
			if u >= rs && u <= re {
				t.Fatalf("route %s unexpectedly covers CN/private IP %s", r.String(), s)
			}
		}
	}
	t.Logf("bypass routes: %d", len(routes))
}

func TestBuildTunConfigValid(t *testing.T) {
	node := NodeItem{
		Protocol: "Shadowsocks", Address: "cm.ktno.cc", Port: 456,
		Method: "chacha20-ietf-poly1305", UUID: "pw",
	}
	tmp := t.TempDir()
	srs := filepath.Join(tmp, "geosite-cn.srs")
	if err := os.WriteFile(srs, geositeCnSrs, 0644); err != nil {
		t.Fatal(err)
	}
	// 用真实 sing-box 校验配置合法性
	sb := filepath.Join(os.Getenv("APPDATA"), "KNcloud", "sing-box.exe")
	if _, err := os.Stat(sb); err != nil {
		t.Skip("sing-box.exe not found")
	}

	// 物理出口网卡名：优先用探测函数，拿不到就退回第一个非回环网卡
	bindIface := physicalInterfaceName("223.5.5.5")
	if bindIface == "" {
		if ifaces, err := net.Interfaces(); err == nil {
			for _, it := range ifaces {
				if it.Flags&net.FlagLoopback == 0 && it.Name != tunIfaceName {
					bindIface = it.Name
					break
				}
			}
		}
	}

	for _, bind := range []string{"", bindIface} {
		cfgJSON, err := buildTunConfigJSON(node, srs, bind)
		if err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(tmp, fmt.Sprintf("cfg_%d.json", len(bind)))
		if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(sb, "check", "-c", cfgPath).CombinedOutput()
		if err != nil {
			t.Fatalf("sing-box check failed (bind=%q): %v\n%s\nconfig:\n%s", bind, err, out, cfgJSON)
		}
		// bind_interface 必须真的出现在 direct / proxy 出站里，否则防环路形同虚设
		if bind != "" {
			if !strings.Contains(cfgJSON, `"bind_interface":"`+bind+`"`) {
				t.Fatalf("bind_interface not injected into config: %s", cfgJSON)
			}
		}
		t.Logf("sing-box check OK (bind=%q)", bind)
	}
}

func TestBestRouteFromRows(t *testing.T) {
	// mkRoute 生成旧式 DWORD 路由行（IP 存网络序 DWORD）
	mkRoute := func(destCIDR, nextHop string, ifIdx, metric uint32) mibIPForwardRow {
		_, ipnet, err := net.ParseCIDR(destCIDR)
		if err != nil {
			t.Fatal(err)
		}
		nh := uint32(0)
		if nextHop != "" {
			nh = ipToDword(net.ParseIP(nextHop))
		}
		return mibIPForwardRow{
			Dest:    ipToDword(ipnet.IP),
			Mask:    ipToDword(net.IP(ipnet.Mask)),
			NextHop: nh,
			IfIndex: ifIdx,
			Metric1: metric,
		}
	}
	rows := []mibIPForwardRow{
		mkRoute("0.0.0.0/0", "172.16.0.1", 5, 200),   // 物理默认路由
		mkRoute("0.0.0.0/0", "10.0.0.1", 7, 9000),    // 另一默认路由（metric 更差）
		mkRoute("172.16.0.0/12", "", 5, 1),           // on-link 局域网（PPPoE 场景）
		mkRoute("104.16.0.0/32", "172.16.0.1", 5, 1), // 与目标无关的 host 路由
		mkRoute("0.0.0.0/0", "172.19.0.1", 99, 1),    // TUN 网卡上的路由，应被排除
	}

	// 海外 IP：无更长前缀命中 → 默认路由里 metric 最小的胜出
	r, ok := bestRouteFromRows(rows, net.ParseIP("8.8.8.8"), 99)
	if !ok || dwordToIP(r.NextHop).String() != "172.16.0.1" {
		t.Fatalf("expected default via 172.16.0.1, got ok=%v nextHop=%v", ok, dwordToIP(r.NextHop))
	}

	// 局域网 IP：最长前缀 /12 胜出，NextHop 保持 on-link (0.0.0.0)
	r, ok = bestRouteFromRows(rows, net.ParseIP("172.16.3.9"), 99)
	if !ok || r.NextHop != 0 {
		t.Fatalf("expected on-link /12 route, got ok=%v nextHop=%v", ok, dwordToIP(r.NextHop))
	}

	// 最优默认路由缺失时，回退到另一条默认路由
	withoutBest := []mibIPForwardRow{rows[1], rows[2], rows[3], rows[4]}
	r, ok = bestRouteFromRows(withoutBest, net.ParseIP("8.8.8.8"), 99)
	if !ok || dwordToIP(r.NextHop).String() != "10.0.0.1" {
		t.Fatalf("expected fallback default via 10.0.0.1, got ok=%v nextHop=%v", ok, dwordToIP(r.NextHop))
	}

	// 只剩 TUN 网卡上的路由 → 全部被排除，无可用路由
	if _, ok := bestRouteFromRows(rows[4:5], net.ParseIP("8.8.8.8"), 99); ok {
		t.Fatalf("expected no route")
	}
}

func TestGetIpForwardTableAndBestRoute(t *testing.T) {
	// 真机路由表读取：旧 API 必须能枚举且字段与 route print 语义一致
	rows, err := getIpForwardTable()
	if err != nil {
		t.Skipf("getIpForwardTable failed (non-Windows?): %v", err)
	}
	if len(rows) < 3 {
		t.Fatalf("route table suspiciously small: %d rows", len(rows))
	}
	defaultN := 0
	for _, r := range rows {
		if r.Mask == 0 && r.Dest == 0 {
			defaultN++
			t.Logf("default route: gw=%s ifIdx=%d metric=%d type=%d",
				dwordToIP(r.NextHop), r.IfIndex, r.Metric1, r.Type)
		}
	}
	if defaultN == 0 {
		t.Fatalf("no default route found in %d rows", len(rows))
	}

	// GetBestRoute：海外 IP 必须解析出一条可用路由
	if br, ok := getBestRoute(net.ParseIP("8.8.8.8")); ok {
		t.Logf("GetBestRoute(8.8.8.8): gw=%s ifIdx=%d metric=%d",
			dwordToIP(br.NextHop), br.IfIndex, br.Metric1)
		if br.IfIndex == 0 {
			t.Fatalf("GetBestRoute returned ifIdx 0")
		}
	} else {
		t.Fatalf("GetBestRoute failed")
	}
}

// TestParseOwnWintunDeviceIDs 覆盖残留 wintun 设备识别。
// 关键回归点：pnputil 实际输出的实例 ID 是 "SWD\Wintun\"（仅首字母大写），
// 旧实现按全大写 "SWD\WINTUN\" 做大小写敏感匹配，导致永远清理不掉残留设备。
func TestParseOwnWintunDeviceIDs(t *testing.T) {
	const chineseOutput = `Microsoft PnP 工具

实例 ID:                SWD\Wintun\{72312B66-D2DE-2908-88D7-1344B4C396A9}
设备描述:         sing-tun Tunnel
类名:                 Net
类 GUID:                 {4d36e972-e325-11ce-bfc1-08002be10318}
制造商名称:          WireGuard LLC
状态:                     已断开连接
驱动程序名称:                oem23.inf

实例 ID:                SWD\WINTUN\{F3B97229-AC55-706A-1D78-803E273E9A86}
设备描述:         sing-tun Tunnel
类名:                 Net
状态:                     已断开连接

实例 ID:                SWD\Wintun\{AAAA0000-0000-0000-0000-000000000001}
设备描述:         WireGuard Tunnel
类名:                 Net
状态:                     已断开连接

实例 ID:                SWD\Wintun\{CCCC0000-0000-0000-0000-000000000003}
设备描述:         Xray Tunnel
类名:                 Net
状态:                     已断开连接

实例 ID:                SWD\MMDEVAPI\{0.0.1.00000000}.{02cdbcfa-0283-4c69-b633-c31b37e7c5a1}
设备描述:         Line In (High Definition Audio Device)
状态:                     已断开连接
`

	got := parseOwnWintunDeviceIDs(chineseOutput)
	if len(got) != 3 {
		t.Fatalf("expected 3 own wintun devices, got %d: %v", len(got), got)
	}
	for _, id := range got {
		if !strings.HasPrefix(id, `SWD\Wintun\`) && !strings.HasPrefix(id, `SWD\WINTUN\`) {
			t.Fatalf("unexpected id %q", id)
		}
		if strings.Contains(id, "AAAA0000") {
			t.Fatalf("foreign WireGuard device must not be removed: %q", id)
		}
	}
	xrayLeftover := `SWD\Wintun\{CCCC0000-0000-0000-0000-000000000003}`
	foundXray := false
	for _, id := range got {
		if id == xrayLeftover {
			foundXray = true
		}
	}
	if !foundXray {
		t.Fatalf("early Xray-mode leftover adapter must be cleaned: %v", got)
	}

	// 英文系统输出同样要能识别
	const englishOutput = `Microsoft PnP Utility

Instance ID:            SWD\Wintun\{BBBB0000-0000-0000-0000-000000000002}
Device Description:     sing-tun Tunnel
Class Name:             Net
Status:                 Disconnected
`
	if got := parseOwnWintunDeviceIDs(englishOutput); len(got) != 1 {
		t.Fatalf("english output: expected 1 device, got %d: %v", len(got), got)
	}

	// 没有任何 wintun 设备时必须返回空，避免误删
	if got := parseOwnWintunDeviceIDs("Microsoft PnP 工具\n\n实例 ID:  USB\\ROOT_HUB\\4&5a7864a&0\n"); len(got) != 0 {
		t.Fatalf("expected no devices, got %v", got)
	}
}

func TestIndexFoldASCII(t *testing.T) {
	if got := indexFoldASCII(`SWD\WINTUN\{X}`, `swd\wintun\`); got != 0 {
		t.Fatalf("case-insensitive match at 0 expected, got %d", got)
	}
	if got := indexFoldASCII(`nothing here`, `SWD\WINTUN\`); got != -1 {
		t.Fatalf("expected -1, got %d", got)
	}
	if got := indexFoldASCII(``, `abc`); got != -1 {
		t.Fatalf("expected -1 for empty haystack, got %d", got)
	}
	// 中文（GBK/UTF-8）前缀不得影响 ASCII 子串定位
	line := `实例 ID:                SWD\Wintun\{X}`
	got := indexFoldASCII(line, `SWD\WINTUN\`)
	if got < 0 {
		t.Fatalf("expected to find id prefix in %q", line)
	}
	if line[got:got+len(`SWD\Wintun\`)] != `SWD\Wintun\` {
		t.Fatalf("found at wrong offset: %q", line[got:])
	}
}
