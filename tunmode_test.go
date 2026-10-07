package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func coreRulesOf(t *testing.T, a *App, node NodeItem) []ruleObj {
	t.Helper()
	cfg, err := a.buildCoreConfigJSON(node)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Routing struct {
			Rules []ruleObj `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.Routing.Rules
}

func rulesMention(rules []ruleObj, s string) bool {
	for _, r := range rules {
		if strings.Contains(strings.Join(append(append([]string{}, r.Domain...), r.IP...), ","), s) {
			return true
		}
	}
	return false
}

// TUN 模式 = 全局接管：不论保存的策略是什么，TUN 下的 Xray 规则都是 global，
// 且不改写用户保存的策略（关 TUN 后按它回到系统代理模式）。
func TestTunAlwaysGlobalKeepsSavedPolicy(t *testing.T) {
	node := NodeItem{ID: "s", Protocol: "Shadowsocks", Address: "1.2.3.4", Port: 8388, Method: "aes-128-gcm", UUID: "pw", Network: "tcp"}
	for _, saved := range []string{"bypass-cn", "direct", "global", "proxy-cn"} {
		a := &App{routingMode: saved, settings: AppSettings{SocksPort: 10808, HttpPort: 10809, DnsServers: "1.1.1.1"}}
		a.tunEgressIface = "以太网"
		rules := coreRulesOf(t, a, node)
		if rulesMention(rules, "geoip:cn") || rulesMention(rules, "geosite:cn") {
			t.Fatalf("saved=%s: TUN must route globally, got CN split rules %+v", saved, rules)
		}
		last := rules[len(rules)-1]
		if last.OutboundTag != "proxy" || !rulesMention(rules, "geoip:private") {
			t.Fatalf("saved=%s: TUN rules must be private→direct, rest→proxy: %+v", saved, rules)
		}
		if a.routingMode != saved {
			t.Fatalf("TUN config rewrote saved policy %s → %s", saved, a.routingMode)
		}
		a.tunEgressIface = ""
		if saved == "bypass-cn" && !rulesMention(coreRulesOf(t, a, node), "geoip:cn") {
			t.Fatal("system-proxy bypass-cn must keep CN split rules")
		}
	}
}

// TUN 运行中选择任一策略 = 关 TUN 并按该策略回到系统代理模式（四个模式互斥）。
func TestSetRoutingModeLeavesTun(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	for _, mode := range []string{"bypass-cn", "global", "direct"} {
		a := &App{tunRunning: true, routingMode: "bypass-cn", settings: AppSettings{SocksPort: 10808, HttpPort: 10809}}
		a.SetRoutingMode(mode)
		if a.tunRunning {
			t.Fatalf("%s: TUN still running", mode)
		}
		if a.routingMode != mode {
			t.Fatalf("%s: routingMode=%s", mode, a.routingMode)
		}
		st := a.GetCoreStatus()
		if st.TunnelMode || st.RoutingMode != mode {
			t.Fatalf("%s: status %+v", mode, st)
		}
	}
}

// TUN 暂停的系统代理在关 TUN 后恢复；TUN 期间用户切换系统代理只记录选择。
func TestSystemProxyPausedDuringTun(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	a := &App{tunRunning: true, tunPausedSysProxy: false, settings: AppSettings{SocksPort: 10808, HttpPort: 10809}}
	if on, err := a.ToggleSystemProxy(true); err != nil || on {
		t.Fatalf("toggle during TUN: on=%v err=%v (must not apply yet)", on, err)
	}
	if !a.tunPausedSysProxy {
		t.Fatal("preference not recorded")
	}
	// 内核未运行：只记下「应开启」，不写注册表
	a.tunSoftStopLocked()
	if !a.systemProxy || a.tunPausedSysProxy {
		t.Fatalf("after TUN stop: systemProxy=%v paused=%v", a.systemProxy, a.tunPausedSysProxy)
	}
}
