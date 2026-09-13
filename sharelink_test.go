package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

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

	vmJSON := `{"v":"2","ps":"VM-节点","add":"vm.example.com","port":"443","id":"2c56a81e-1287-44df-9d33-149b106c28f3","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ray","tls":"tls","sni":"vm.example.com"}`
	vm := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmJSON))
	n, err = ParseShareLink(vm)
	if err != nil {
		t.Fatalf("vmess: %v", err)
	}
	if n.Protocol != "VMess" || n.Address != "vm.example.com" || n.Port != 443 || n.Network != "ws" || n.Path != "/ray" || n.Security != "tls" {
		t.Fatalf("vmess parse wrong: %+v", n)
	}

	batch := strings.Join([]string{vless, trojan, ssSIP002, vm, "https://not-a-proxy-link"}, "\n")
	nodes := ParseShareLinks(batch)
	if len(nodes) != 4 {
		t.Fatalf("batch expected 4 nodes, got %d", len(nodes))
	}

	// 整段 base64 订阅内容
	b64Sub := base64.StdEncoding.EncodeToString([]byte(batch))
	nodes = ParseShareLinks(b64Sub)
	if len(nodes) != 4 {
		t.Fatalf("b64 sub expected 4 nodes, got %d", len(nodes))
	}
}
