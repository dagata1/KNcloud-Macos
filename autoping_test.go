package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

// 测速临时实例：TUN 未开时不绑网卡；TUN 开启时 proxy 出站绑物理网卡（不经当前节点），
// 两种配置都不开 mux，且 Xray 能构建。
func TestRealDelayTestConfigEgressBinding(t *testing.T) {
	nodes := []NodeItem{
		{ID: "s", Protocol: "Shadowsocks", Address: "ss.example.com", Port: 8388, Method: "aes-128-gcm", UUID: "pw", Network: "tcp"},
		{ID: "v", Protocol: "VLESS", Address: "v.example.com", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "ws", Security: "tls", Path: "/ws", SNI: "v.example.com"},
	}
	for _, node := range nodes {
		for _, iface := range []string{"", "以太网"} {
			cfg, err := realDelayTestConfig(node, 23456, iface, "")
			if err != nil {
				t.Fatalf("%s/%q: %v", node.Protocol, iface, err)
			}
			data, _ := json.Marshal(cfg)
			var parsed struct {
				Outbounds []struct {
					Tag            string                 `json:"tag"`
					Mux            map[string]interface{} `json:"mux"`
					StreamSettings struct {
						Sockopt map[string]interface{} `json:"sockopt"`
					} `json:"streamSettings"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
			if len(parsed.Outbounds) != 1 || parsed.Outbounds[0].Tag != "proxy" {
				t.Fatalf("%s/%q: want a single proxy outbound, got %+v", node.Protocol, iface, parsed.Outbounds)
			}
			out := parsed.Outbounds[0]
			if en, _ := out.Mux["enabled"].(bool); en {
				t.Fatalf("%s/%q: test outbound must not use mux", node.Protocol, iface)
			}
			got, _ := out.StreamSettings.Sockopt["interface"].(string)
			if got != iface {
				t.Fatalf("%s: sockopt.interface = %q, want %q", node.Protocol, got, iface)
			}
			pb, err := serial.DecodeJSONConfig(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("%s/%q: decode: %v", node.Protocol, iface, err)
			}
			if _, err := pb.Build(); err != nil {
				t.Fatalf("%s/%q: build: %v", node.Protocol, iface, err)
			}
		}
	}
}

// 单测环境（无 Wails ctx）里刷新订阅等触发点不会真的启动测速。
func TestRequestAutoPingNoopWithoutRuntime(t *testing.T) {
	a := &App{nodes: []NodeItem{{ID: "x", Protocol: "Shadowsocks", Address: "127.0.0.1", Port: 1}}}
	a.requestAutoPing()
	if a.IsAutoPinging() {
		t.Fatal("auto ping must not start without a Wails context")
	}
}
