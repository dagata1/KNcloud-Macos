package main

import (
	"testing"
	"time"
)

func TestSubUpdateInterval(t *testing.T) {
	if subUpdateInterval(-1) != 0 {
		t.Fatal("-1 should disable")
	}
	week := 7 * 24 * time.Hour
	if subUpdateInterval(0) != week {
		t.Fatal("0 should be weekly")
	}
	if subUpdateInterval(12) != week || subUpdateInterval(6) != week {
		t.Fatal("legacy hour values should be weekly")
	}
}

func TestSubAutoUpdateDue(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	if subAutoUpdateDue(now, 0, time.Hour) {
		t.Fatal("no last -> not due")
	}
	if subAutoUpdateDue(now, now.Add(-59*time.Minute).Unix(), time.Hour) {
		t.Fatal("59m < 1h")
	}
	if !subAutoUpdateDue(now, now.Add(-61*time.Minute).Unix(), time.Hour) {
		t.Fatal("61m >= 1h")
	}
	if subAutoUpdateDue(now, now.Add(-10*time.Hour).Unix(), 0) {
		t.Fatal("disabled")
	}
}
