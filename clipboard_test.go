package main

import "testing"

// TestClipboardRoundTrip 验证 Win32 剪贴板 UTF-16 读写的往返一致性（含中文）。
// 测试会临时改写系统剪贴板，结束时恢复原内容。
func TestClipboardRoundTrip(t *testing.T) {
	orig, _ := clipboardText()

	const want = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpmNGMwZTliZS1hYWM2LTRlNTItODE1Ni02YzdhMTg4MmJiZGY@jp.kncloud.top:456?#日本[V6]"
	if err := setClipboardText(want); err != nil {
		t.Skipf("clipboard unavailable in test environment: %v", err)
	}
	got, err := clipboardText()
	if err != nil {
		t.Fatalf("clipboardText: %v", err)
	}
	if got != want {
		t.Fatalf("clipboard roundtrip mismatch:\nwant %q\ngot  %q", want, got)
	}

	if orig != "" {
		_ = setClipboardText(orig)
	}
}
