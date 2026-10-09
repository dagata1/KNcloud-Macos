package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.3.26", "v1.3.26", 0},
		{"v1.3.27", "v1.3.26", 1},
		{"v1.3.26", "v1.3.27", -1},
		{"v1.10.0", "v1.9.9", 1},
		{"v2.0.0", "v1.99.99", 1},
		{"1.3.26", "v1.3.26", 0},
		{"v1.4", "v1.3.99", 1},
		{"v1.4", "v1.4.0", 0},
		{"v1.4.0", "v1.4.0-beta.1", 1},
		{"v1.4.0-beta.2", "v1.4.0-beta.10", -1},
		{"v1.4.0-alpha", "v1.4.0-beta", -1},
		{"v1.4.0-rc.1", "v1.4.0-rc.1.1", -1},
		{"dev", "v1.3.26", 0},
		{"v1.3.26", "abc1234", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if !isDevVersion("dev") || isDevVersion("v1.3.26") {
		t.Fatal("isDevVersion wrong")
	}
}

func TestParseSHA256File(t *testing.T) {
	h := strings.Repeat("ab", 32)
	if got, err := parseSHA256File([]byte(h+"  KNcloud-WIN-v1.3.27.zip\n"), "KNcloud-WIN-v1.3.27.zip"); err != nil || got != h {
		t.Fatalf("sha256sum format: %q %v", got, err)
	}
	if got, err := parseSHA256File([]byte(strings.ToUpper(h)+" *dist/KNcloud-WIN-v1.3.27.zip"), "KNcloud-WIN-v1.3.27.zip"); err != nil || got != h {
		t.Fatalf("binary marker/path: %q %v", got, err)
	}
	if got, err := parseSHA256File([]byte(h), "x.zip"); err != nil || got != h {
		t.Fatalf("bare hash: %q %v", got, err)
	}
	if _, err := parseSHA256File([]byte(h+"  other.zip"), "KNcloud-WIN-v1.3.27.zip"); err == nil {
		t.Fatal("hash for another file accepted")
	}
	if _, err := parseSHA256File([]byte("not a hash"), "x"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
}

func TestSafeJoinRejectsEscapes(t *testing.T) {
	dest := t.TempDir()
	bad := []string{"../evil.exe", "KNcloud/../../evil", "/abs/path", "\\abs", "C:\\Windows\\x.dll", "c:evil", "a/../../b", "..\\..\\x", ""}
	for _, n := range bad {
		if _, err := safeJoin(dest, n); err == nil {
			t.Errorf("safeJoin accepted %q", n)
		}
	}
	good := []string{"KNcloud.exe", "bin/wintun.dll", "bin\\geoip.dat", "bin/sub/x.txt"}
	for _, n := range good {
		p, err := safeJoin(dest, n)
		if err != nil {
			t.Errorf("safeJoin rejected %q: %v", n, err)
			continue
		}
		if !strings.HasPrefix(p, dest) {
			t.Errorf("%q escaped: %s", n, p)
		}
	}
}

func TestExtractUpdateZipSlip(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "evil.zip")
	writeZip(t, zp, map[string]string{
		"KNcloud/KNcloud.exe":     "MZ",
		"KNcloud/../../pwned.txt": "x",
	})
	out := filepath.Join(dir, "out")
	if _, err := extractUpdateZip(zp, out); err == nil {
		t.Fatal("zip-slip entry was extracted")
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned.txt")); err == nil {
		t.Fatal("file written outside destination")
	}
	zp2 := filepath.Join(dir, "evil2.zip")
	writeZip(t, zp2, map[string]string{"../x.txt": "x"})
	if _, err := extractUpdateZip(zp2, filepath.Join(dir, "out2")); err == nil {
		t.Fatal("top-level ../ accepted")
	}
}
