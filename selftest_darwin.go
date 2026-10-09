//go:build darwin

package main

// selftest_darwin.go —— KNcloud --core-selftest：不开窗口，验证内嵌 Xray 内核可用
// （CI 冒烟）：起一个本地 HTTP 服务，Xray 开 127.0.0.1 SOCKS 入站 + freedom 出站，
// 经 SOCKS 访问该 HTTP 服务；同时加载 .app 内的 geoip/geosite 规则，验证资源打包无误。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func runCoreSelfTest() int {
	fail := func(step string, err error) int {
		fmt.Printf("[FAIL] %s: %v\n", step, err)
		return 1
	}
	assetDir, err := ensureGeoAssets()
	if err != nil {
		return fail("geo assets", err)
	}
	os.Setenv("xray.location.asset", assetDir)
	fmt.Println("[ OK ] geo assets in", assetDir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail("listen http", err)
	}
	const body = "kncloud-core-selftest-ok"
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))

	socksPort := pickFreeLoopbackPort()
	if socksPort == 0 {
		return fail("pick port", fmt.Errorf("no free port"))
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
		}},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
			map[string]any{"type": "field", "domain": []string{"geosite:category-ads-all"}, "outboundTag": "block"},
		}},
	}
	data, _ := json.Marshal(cfg)
	pb, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return fail("decode config", err)
	}
	cc, err := pb.Build()
	if err != nil {
		return fail("build config (geo rules)", err)
	}
	inst, err := xcore.New(cc)
	if err != nil {
		return fail("core.New", err)
	}
	if err := inst.Start(); err != nil {
		return fail("core start", err)
	}
	defer inst.Close()
	fmt.Printf("[ OK ] Xray-core %s started, SOCKS 127.0.0.1:%d\n", xrayCoreVersion(), socksPort)

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	var got string
	for i := 0; i < 20; i++ {
		resp, err := client.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			got = string(b)
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if got != body {
		return fail("HTTP via SOCKS", fmt.Errorf("unexpected body %q", got))
	}
	fmt.Println("[ OK ] HTTP request through Xray SOCKS inbound")
	fmt.Println("[PASS] core self-test")
	return 0
}
