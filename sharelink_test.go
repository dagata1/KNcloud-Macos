package main

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestShareLinkRoundTrip 用测试示例 ss 链接验证 SIP002 解析，
// 并对全部协议做「解析 → 生成 → 再解析」往返一致性检查。
func TestShareLinkRoundTrip(t *testing.T) {
	const realSS = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3M@ss.example.test:456?#%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B9`
	n, err := ParseShareLink(realSS)
	if err != nil {
		t.Fatalf("sample ss link parse: %v", err)
	}
	if n.Protocol != "Shadowsocks" || n.Address != "ss.example.test" || n.Port != 456 ||
		n.Method != "chacha20-ietf-poly1305" || n.UUID != "test-pass" || n.Name != "测试节点" {
		t.Fatalf("sample ss parse wrong: %+v", n)
	}

	samples := []NodeItem{
		{Protocol: "Shadowsocks", Name: "测试节点", Address: "ss.example.test", Port: 456,
			Method: "chacha20-ietf-poly1305", UUID: "test-pass", Security: "none"},
		{Protocol: "VLESS", Name: "香港01", Address: "hk.example.com", Port: 443, UUID: "u1",
			Security: "reality", Network: "grpc", SNI: "www.apple.com", FP: "chrome",
			PBK: "pbk-x", SID: "6ba85179", ServiceName: "grpc-stream"},
		{Protocol: "Trojan", Name: "JP-WS", Address: "jp.example.io", Port: 8443, UUID: "pw",
			Security: "tls", Network: "ws", Path: "/ws", HostName: "cdn.example.io"},
		{Protocol: "VMess", Name: "US", Address: "us.example.org", Port: 10086, UUID: "vm-id",
			Security: "tls", Network: "ws", Path: "/vm", HostName: "h.example.org", AlterID: 0},
		{Protocol: "Hysteria2", Name: "HY2", Address: "hy.example.net", Port: 24433, UUID: "hy-pw",
			Security: "tls", Network: "udp"},
		{Protocol: "AnyTLS", Name: "极限量-2", Address: "at.example.cn", Port: 443, UUID: "9sK2mP8xQ7vL3nZ6",
			Security: "tls", Network: "tcp", SNI: "at.example.cn", Insecure: true},
	}
	for _, src := range samples {
		link, err := BuildShareLink(src)
		if err != nil {
			t.Fatalf("BuildShareLink(%s): %v", src.Protocol, err)
		}
		got, err := ParseShareLink(link)
		if err != nil {
			t.Fatalf("roundtrip %s: parse %q: %v", src.Protocol, link, err)
		}
		// 归一化解析器补的默认值（Network 空 = tcp；Delay 是测试状态不是链接内容；
		// SNI 缺省 = 服务器地址）
		if got.Network == "tcp" && src.Network == "" {
			got.Network = ""
		}
		got.Delay = 0
		// 解析器对缺省字段有兜底：URI 协议 SNI←地址；VMess SNI←host、ServiceName←path
		wantSNI := src.SNI
		switch src.Protocol {
		case "VMess":
			if wantSNI == "" {
				wantSNI = src.HostName
			}
		case "Shadowsocks":
			// 不填 SNI
		default:
			if wantSNI == "" {
				wantSNI = src.Address
			}
		}
		wantSvc := src.ServiceName
		if src.Protocol == "VMess" {
			wantSvc = src.Path
		}
		if got.Protocol != src.Protocol || got.Address != src.Address || got.Port != src.Port ||
			got.Name != src.Name || got.UUID != src.UUID || got.Network != src.Network ||
			got.Security != src.Security || got.Method != src.Method || got.Path != src.Path ||
			got.SNI != wantSNI || got.PBK != src.PBK || got.SID != src.SID ||
			got.HostName != src.HostName || got.ServiceName != wantSvc {
			rv, sv := reflect.ValueOf(got), reflect.ValueOf(src)
			rt := rv.Type()
			var diffs []string
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i).Name
				if !reflect.DeepEqual(rv.Field(i).Interface(), sv.Field(i).Interface()) {
					diffs = append(diffs, fmt.Sprintf("%s: want %q got %q", f, sv.Field(i).Interface(), rv.Field(i).Interface()))
				}
			}
			t.Fatalf("roundtrip %s mismatch, diffs=%v\nwant %+v\ngot  %+v\nlink: %s", src.Protocol, diffs, src, got, link)
		}
	}

	// 剪贴板常见形态：多行链接混合空行
	linkOf := func(n NodeItem) string {
		t.Helper()
		l, err := BuildShareLink(n)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	multi := linkOf(samples[0]) + "\n\n" + linkOf(samples[4])
	if got := ParseShareLinks(multi); len(got) != 2 {
		t.Fatalf("ParseShareLinks multi-line: got %d nodes", len(got))
	}
}

func TestShareLink(t *testing.T) {
	vless := "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@hk01.example.com:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179&type=grpc&serviceName=grpc-stream#%E9%A6%99%E6%B8%AF01"
	n, err := ParseShareLink(vless)
	if err != nil {
		t.Fatalf("vless: %v", err)
	}
	if n.Protocol != "VLESS" || n.Address != "hk01.example.com" || n.Port != 443 || n.SNI != "www.apple.com" || n.PBK == "" || n.Network != "grpc" || n.Name != "香港01" {
		t.Fatalf("vless parse wrong: %+v", n)
	}

	trojan := "trojan://pass-word@jp.example.io:8443?security=tls&type=ws&path=%2Fws&host=cdn.example.io#JP-WS"
	n, err = ParseShareLink(trojan)
	if err != nil {
		t.Fatalf("trojan: %v", err)
	}
	if n.Protocol != "Trojan" || n.UUID != "pass-word" || n.Port != 8443 || n.Network != "ws" || n.Path != "/ws" || n.HostName != "cdn.example.io" {
		t.Fatalf("trojan parse wrong: %+v", n)
	}

	ssSIP002 := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test-pass")) + "@ss.example.net:8388#SS-Node"
	n, err = ParseShareLink(ssSIP002)
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	if n.Protocol != "Shadowsocks" || n.Method != "aes-256-gcm" || n.UUID != "test-pass" || n.Address != "ss.example.net" || n.Port != 8388 {
		t.Fatalf("ss parse wrong: %+v", n)
	}

	anytls := "anytls://9sK2mP8xQ7vL3nZ6@ac7548f3ebe045b39a90288ff1e97526.pnuqcnp.cn:443?security=tls&insecure=1&allowInsecure=1&type=tcp&headerType=none#%E6%9E%81%E9%99%90%E9%87%8F"
	n, err = ParseShareLink(anytls)
	if err != nil {
		t.Fatalf("anytls: %v", err)
	}
	if n.Protocol != "AnyTLS" || n.Address != "ac7548f3ebe045b39a90288ff1e97526.pnuqcnp.cn" || n.Port != 443 ||
		n.UUID != "9sK2mP8xQ7vL3nZ6" || n.Security != "tls" || n.Network != "tcp" || !n.Insecure ||
		n.SNI != "ac7548f3ebe045b39a90288ff1e97526.pnuqcnp.cn" {
		t.Fatalf("anytls parse wrong: %+v", n)
	}
	// 缺省 insecure 时不应误开
	n, err = ParseShareLink("anytls://pw@at.example.cn:8443#at")
	if err != nil {
		t.Fatalf("anytls plain: %v", err)
	}
	if n.Insecure || n.Security != "tls" || n.Network != "tcp" {
		t.Fatalf("anytls defaults wrong: %+v", n)
	}

	vmJSON := `{"v":"2","ps":"VM-节点","add":"vm.example.com","port":"443","id":"2c56a81e-1287-44df-9d33-149b106c28f3","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ray","tls":"tls","sni":"vm.example.com"}`
	vm := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmJSON))
	n, err = ParseShareLink(vm)
	if err != nil {
		t.Fatalf("vmess: %v", err)
	}
	if n.Protocol != "VMess" || n.Address != "vm.example.com" || n.Port != 443 || n.Network != "ws" || n.Path != "/ray" || n.Security != "tls" {
		t.Fatalf("vmess parse wrong: %+v", n)
	}

	batch := strings.Join([]string{vless, trojan, ssSIP002, vm, anytls, "https://not-a-proxy-link"}, "\n")
	nodes, skipped := ParseShareLinksReport(batch)
	if len(nodes) != 5 || len(skipped) != 0 {
		t.Fatalf("batch expected 5 nodes, got %d nodes, skipped=%v", len(nodes), skipped)
	}

	// 整段 base64 订阅内容
	b64Sub := base64.StdEncoding.EncodeToString([]byte(batch))
	nodes = ParseShareLinks(b64Sub)
	if len(nodes) != 5 {
		t.Fatalf("b64 sub expected 5 nodes, got %d", len(nodes))
	}
}
