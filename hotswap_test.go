package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// newTestCore 起一个最小内核：一个 SOCKS5 入站 + 一个 tag 为 proxy 的 freedom 出站。
// 不依赖 geo 资源与真实节点，因此可在 CI 上直接跑。
func newTestCore(t *testing.T) *xcore.Instance {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法绑定本地端口，跳过: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	cfg := fmt.Sprintf(`{
	  "stats": {},
	  "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
	  "inbounds": [{"tag":"socks","port":%d,"listen":"127.0.0.1","protocol":"socks",
	                "settings":{"auth":"noauth","udp":false}}],
	  "outbounds": [{"tag":"%s","protocol":"freedom","settings":{}}]
	}`, port, proxyOutboundTag)

	pb, err := serial.DecodeJSONConfig(bytes.NewReader([]byte(cfg)))
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	full, err := pb.Build()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	inst, err := xcore.New(full)
	if err != nil {
		t.Fatalf("new instance: %v", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		t.Fatalf("start instance: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	time.Sleep(200 * time.Millisecond)
	return inst
}

func proxyHandler(t *testing.T, inst *xcore.Instance) outbound.Handler {
	t.Helper()
	mgr := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	return mgr.GetHandler(proxyOutboundTag)
}

// TestHotSwapReplacesProxyHandler 换节点时应当替换掉 proxy 出站的 handler，
// 而不是重建整个内核 —— 后者会连带销毁入站监听并把累计流量计数清零。
func TestHotSwapReplacesProxyHandler(t *testing.T) {
	inst := newTestCore(t)
	before := proxyHandler(t, inst)
	if before == nil {
		t.Fatal("初始应存在 proxy 出站")
	}

	a := &App{xrayInst: inst}
	a.settings.MuxEnabled = true

	node := NodeItem{
		Name: "hot", Protocol: "VLESS", Address: "127.0.0.1", Port: 12345,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Security: "none", Network: "tcp",
	}
	if err := a.hotSwapProxyOutboundLocked(node); err != nil {
		t.Fatalf("热切换应当成功: %v", err)
	}

	after := proxyHandler(t, inst)
	if after == nil {
		t.Fatal("切换后 proxy 出站不得消失")
	}
	if after == before {
		t.Fatal("handler 未被替换，热切换没有生效")
	}
	if after.Tag() != proxyOutboundTag {
		t.Fatalf("新 handler 的 tag 应为 %q，实际 %q", proxyOutboundTag, after.Tag())
	}
}

// TestHotSwapRejectsUnsupportedProtocol 不受支持的协议必须在摘除旧 handler 之前
// 就失败，保证现网出站不受影响。
func TestHotSwapRejectsUnsupportedProtocol(t *testing.T) {
	inst := newTestCore(t)
	before := proxyHandler(t, inst)

	a := &App{xrayInst: inst}
	err := a.hotSwapProxyOutboundLocked(NodeItem{
		Name: "hy2", Protocol: "Hysteria2", Address: "127.0.0.1", Port: 24433, UUID: "pw",
	})
	if err == nil {
		t.Fatal("Hysteria2 应当被拒绝")
	}
	if !strings.Contains(err.Error(), "Hysteria2") {
		t.Fatalf("错误应点名协议，实际: %v", err)
	}

	after := proxyHandler(t, inst)
	if after == nil {
		t.Fatal("失败后 proxy 出站不得消失")
	}
	if after != before {
		t.Fatal("失败后不应替换原有 handler")
	}
}

// TestHotSwapWithoutCoreReportsUnavailable 内核未运行时返回 errHotSwapUnavailable，
// 由 SelectNode 回退到整体启动，而不是 panic。
func TestHotSwapWithoutCoreReportsUnavailable(t *testing.T) {
	a := &App{}
	err := a.hotSwapProxyOutboundLocked(NodeItem{
		Protocol: "VLESS", Address: "127.0.0.1", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "tcp",
	})
	if err != errHotSwapUnavailable {
		t.Fatalf("应返回 errHotSwapUnavailable，实际: %v", err)
	}
}

// TestSelectNodeRollsBackOnRejectedNode 新节点无法装入内核时，SelectNode 必须
// 回滚到切换前的节点：选择状态退回，现网出站原样保留，内核不被重启。
func TestSelectNodeRollsBackOnRejectedNode(t *testing.T) {
	useTempConfigDir(t)
	inst := newTestCore(t)
	before := proxyHandler(t, inst)

	a := &App{xrayInst: inst, coreRunning: true}
	a.nodes = []NodeItem{
		{ID: "good", Name: "good", Protocol: "VLESS", Address: "127.0.0.1", Port: 443,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "tcp", Active: true},
		{ID: "hy2", Name: "hy2", Protocol: "Hysteria2", Address: "127.0.0.1", Port: 24433, UUID: "pw"},
	}
	a.activeNodeID = "good"
	a.coreNodeID = "good"

	if _, err := a.SelectNode("hy2"); err == nil {
		t.Fatal("Hysteria2 节点应切换失败")
	}
	if a.activeNodeID != "good" || !a.nodes[0].Active || a.nodes[1].Active {
		t.Fatalf("失败后应回滚到原节点，实际 activeNodeID=%q nodes=%+v", a.activeNodeID, a.nodes)
	}
	if !a.coreRunning || a.xrayInst != inst || a.coreNodeID != "good" {
		t.Fatal("新节点被拒时不应重启或停掉内核")
	}
	if proxyHandler(t, inst) != before {
		t.Fatal("新节点被拒时不应替换现网出站")
	}
}

// TestSelectNodeHotSwapsWithoutRestart 正常换节点应只替换出站，内核实例保持不变。
func TestSelectNodeHotSwapsWithoutRestart(t *testing.T) {
	useTempConfigDir(t)
	inst := newTestCore(t)
	before := proxyHandler(t, inst)

	a := &App{xrayInst: inst, coreRunning: true}
	a.nodes = []NodeItem{
		{ID: "a", Name: "a", Protocol: "VLESS", Address: "127.0.0.1", Port: 443,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "tcp", Active: true},
		{ID: "b", Name: "b", Protocol: "VLESS", Address: "127.0.0.1", Port: 8443,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "tcp"},
	}
	a.activeNodeID = "a"
	a.coreNodeID = "a"

	got, err := a.SelectNode("b")
	if err != nil {
		t.Fatalf("换节点应成功: %v", err)
	}
	if !got.Active || a.activeNodeID != "b" || a.coreNodeID != "b" {
		t.Fatalf("选择状态未更新: got=%+v activeNodeID=%q coreNodeID=%q", got, a.activeNodeID, a.coreNodeID)
	}
	if a.xrayInst != inst {
		t.Fatal("热切换不应重建内核实例")
	}
	if proxyHandler(t, inst) == before {
		t.Fatal("proxy 出站未被替换")
	}
}
