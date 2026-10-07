package main

import (
	"testing"
	"time"
)

func TestSubUpdateInterval(t *testing.T) {
	if subUpdateInterval(-1) != 0 {
		t.Fatal("-1 should disable")
	}
	if subUpdateInterval(0) != 6*time.Hour {
		t.Fatal("0 should default to 6h")
	}
	if subUpdateInterval(12) != 12*time.Hour {
		t.Fatal("12h")
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
