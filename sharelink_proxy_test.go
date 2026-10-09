package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseHTTPSProxyLink(t *testing.T) {
	n, err := ParseShareLink("https://193.176.84.32:9002?skip-cert-verify=true#%E7%BD%97%E9%A9%AC%E5%B0%BC%E4%BA%9A")
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != "HTTP" || n.Security != "tls" || !n.Insecure || n.Address != "193.176.84.32" || n.Port != 9002 || n.Name != "罗马尼亚" || n.SNI != "193.176.84.32" {
		t.Fatalf("bad node: %+v", n)
	}
	n, err = ParseShareLink("https://mrwdfNTD8M79LCukCieldrqZWqs=:exaxgqkKkd0TAMrCxeonWg==@twmoon1-cdn-route.couldflare-cdn.com:1443#x")
	if err != nil {
		t.Fatal(err)
	}
	if n.Username != "mrwdfNTD8M79LCukCieldrqZWqs=" || n.UUID != "exaxgqkKkd0TAMrCxeonWg==" || n.Insecure {
		t.Fatalf("bad auth: %+v", n)
	}
	out, err := buildProxyOutbound(n, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if out["protocol"] != "http" || out["mux"] != nil {
		t.Fatalf("bad outbound: %+v", out)
	}
	ss := out["streamSettings"].(map[string]interface{})
	if ss["security"] != "tls" {
		t.Fatalf("expected tls: %+v", ss)
	}
	link, _ := BuildShareLink(n)
	back, err := ParseShareLink(link)
	if err != nil || back.Username != n.Username || back.UUID != n.UUID || back.Security != "tls" {
		t.Fatalf("roundtrip %s -> %+v %v", link, back, err)
	}
}

func TestParseSocksLink(t *testing.T) {
	n, err := ParseShareLink("socks5://193.200.85.129:1080#s5")
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != "SOCKS" || n.Security != "none" || n.Port != 1080 || n.Username != "" {
		t.Fatalf("bad node: %+v", n)
	}
	n, err = ParseShareLink("socks://dXNlcjpwYXNz@1.2.3.4:1088#v2rayn")
	if err != nil || n.Username != "user" || n.UUID != "pass" {
		t.Fatalf("v2rayN socks: %+v %v", n, err)
	}
	out, err := buildProxyOutbound(n, false, "")
	if err != nil || out["protocol"] != "socks" {
		t.Fatalf("outbound %+v %v", out, err)
	}
	servers := out["settings"].(map[string]interface{})["servers"].([]map[string]interface{})
	users := servers[0]["users"].([]map[string]interface{})
	if users[0]["user"] != "user" || users[0]["pass"] != "pass" {
		t.Fatalf("users %+v", users)
	}
}

func TestSubscriptionURLIsNotProxyNode(t *testing.T) {
	if _, err := ParseShareLink("http://204240.top:8990/c/?token=abc"); err == nil {
		t.Fatal("subscription URL parsed as proxy node")
	}
}

func TestShadowsocksPluginSkipped(t *testing.T) {
	_, err := ParseShareLink("ss://bm9uZTpPREk0WmpBd1pHTXRORFF6@103.11.76.248:80/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com#x")
	if !errors.Is(err, errUnsupportedProtocol) {
		t.Fatalf("want unsupported, got %v", err)
	}
	nodes, skipped := ParseShareLinksReport("ss://bm9uZTpPREk0WmpBd1pHTXRORFF6@103.11.76.248:80/?plugin=simple-obfs#x\nsocks5://1.1.1.1:1080#a")
	if len(nodes) != 1 || skipped["ss"] != 1 || !strings.Contains(skippedLinksLog(skipped), "1 ss") {
		t.Fatalf("nodes=%d skipped=%v", len(nodes), skipped)
	}
}

func TestTLSInsecureHonored(t *testing.T) {
	n, _ := ParseShareLink("trojan://pw@185.220.238.77:11543?allowInsecure=1&sni=185.220.238.77&type=ws&path=%2Fapi#t")
	out, _ := buildProxyOutbound(n, false, "")
	tls := out["streamSettings"].(map[string]interface{})["tlsSettings"].(map[string]interface{})
	if tls["allowInsecure"] != true {
		t.Fatalf("allowInsecure not honored: %+v", tls)
	}
}
