package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAnyTLSBridgeConfigShape(t *testing.T) {
	node := NodeItem{
		Protocol: "AnyTLS", Name: "at", Address: "at.example.cn", Port: 443,
		UUID: "pw", Security: "tls", Network: "tcp", SNI: "at.example.cn", Insecure: true,
	}
	cfg, err := buildAnyTLSBridgeConfig(node, 39871, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"type":"mixed"`, `"listen":"127.0.0.1"`, `"listen_port":39871`,
		`"type":"anytls"`, `"server":"1.2.3.4"`, `"server_port":443`, `"password":"pw"`,
		`"server_name":"at.example.cn"`, `"insecure":true`, `"fingerprint":"chrome"`,
		`"final":"proxy"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("bridge config missing %s: %s", want, cfg)
		}
	}

	// 地址与 SNI 相同且都不是 IP 时不必写 server_name（sing-box 用 server 推导）
	cfg, err = buildAnyTLSBridgeConfig(node, 1, "at.example.cn")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, `"server_name"`) {
		t.Fatalf("server_name should be omitted when it equals server: %s", cfg)
	}

	// 缺密码 / 非法端口必须报错，而不是生成一份跑不起来的配置
	if _, err := buildAnyTLSBridgeConfig(NodeItem{Protocol: "AnyTLS", Port: 443}, 1, "1.2.3.4"); err == nil {
		t.Fatal("expected error for missing password")
	}
	if _, err := buildAnyTLSBridgeConfig(NodeItem{Protocol: "AnyTLS", Port: 0, UUID: "pw"}, 1, "1.2.3.4"); err == nil {
		t.Fatal("expected error for invalid port")
	}
}

// TestAnyTLSBridgeConfigValid 用真实 sing-box 校验桥配置，
// 保证字段名跟内嵌版本对得上（anytls 出站要求 ≥1.12）。
func TestAnyTLSBridgeConfigValid(t *testing.T) {
	// 必须走 ensureSingBoxBin 而不是直接读配置目录下的副本：那份文件可能是
	// 上一版（AnyTLS 之前）释放的旧二进制，用它校验会得到
	// "unknown field \"server\"" 之类的假失败，测的还不是实际发布的版本。
	sb, err := ensureSingBoxBin()
	if err != nil {
		t.Skipf("sing-box.exe unavailable: %v", err)
	}
	tmp := t.TempDir()
	for _, tt := range []struct {
		name     string
		node     NodeItem
		serverIP string
	}{
		{
			name: "insecure+ip",
			node: NodeItem{Protocol: "AnyTLS", Address: "at.example.cn", Port: 443,
				UUID: "pw", Security: "tls", SNI: "at.example.cn", Insecure: true, FP: "chrome"},
			serverIP: "1.2.3.4",
		},
		{
			name: "verify-cert",
			node: NodeItem{Protocol: "AnyTLS", Address: "at.example.cn", Port: 8443,
				UUID: "pw2", Security: "tls", SNI: "cdn.example.com"},
			serverIP: "",
		},
	} {
		cfgJSON, err := buildAnyTLSBridgeConfig(tt.node, 39872, tt.serverIP)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		cfgPath := filepath.Join(tmp, tt.name+".json")
		if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(sb, "check", "-c", cfgPath).CombinedOutput()
		if err != nil {
			t.Fatalf("sing-box check failed (%s): %v\n%s\nconfig:\n%s", tt.name, err, out, cfgJSON)
		}
		t.Logf("sing-box check OK (%s)", tt.name)
	}
}

// TestBuildProxyOutboundAnyTLS 覆盖 Xray 侧退化成 socks 出站的形状。
func TestBuildProxyOutboundAnyTLS(t *testing.T) {
	node := NodeItem{Protocol: "AnyTLS", Address: "at.example.cn", Port: 443, UUID: "pw", Security: "tls"}

	if _, err := buildProxyOutbound(node, false, ""); err == nil {
		t.Fatal("expected error when bridge addr is empty")
	}

	out, err := buildProxyOutbound(node, true, "127.0.0.1:39999")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{`"protocol":"socks"`, `"tag":"proxy"`, `"address":"127.0.0.1"`, `"port":39999`, `"udp":true`} {
		if !strings.Contains(got, want) {
			t.Fatalf("proxy outbound missing %s: %s", want, got)
		}
	}
	// mux 是 VLESS/VMess/Trojan 的特性，桥路径不能带
	if strings.Contains(got, `"mux"`) {
		t.Fatalf("AnyTLS outbound must not set mux: %s", got)
	}
}