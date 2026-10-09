package main

import (
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
