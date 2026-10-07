package main

import (
	"testing"

	xcore "github.com/xtls/xray-core/core"
)

func TestTrafficMeterDeltas(t *testing.T) {
	var m trafficMeter
	i1, i2 := &xcore.Instance{}, &xcore.Instance{}
	m.observe(i1, 100, 1000)
	m.observe(i1, 150, 5000)
	if u, d, tu, td := m.snapshot(); u != 50 || d != 4000 || tu != 150 || td != 5000 {
		t.Fatalf("same instance: %d %d %d %d", u, d, tu, td)
	}
	// 内核重启：新实例计数器从 0 开始，基线归零（而不是把旧值当负增量或整段重复计入）
	m.observe(i2, 10, 20)
	if u, d, tu, td := m.snapshot(); u != 10 || d != 20 || tu != 160 || td != 5020 {
		t.Fatalf("new instance: %d %d %d %d", u, d, tu, td)
	}
	// 内核停止：速率归零、累计不变
	m.observe(nil, 0, 0)
	if u, d, tu, td := m.snapshot(); u != 0 || d != 0 || tu != 160 || td != 5020 {
		t.Fatalf("stopped: %d %d %d %d", u, d, tu, td)
	}
	// 同一实例上计数器回退（不应发生）不产生负数
	m.observe(i2, 30, 40)
	m.observe(i2, 5, 5)
	if _, _, tu, td := m.snapshot(); tu != 190 || td != 5060 {
		t.Fatalf("regress: %d %d", tu, td)
	}
}
