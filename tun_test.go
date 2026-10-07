package main

import (
	"net"
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
