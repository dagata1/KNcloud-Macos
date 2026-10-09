package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractAndInstallUpdate(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "KNcloud-WIN-v9.9.9.zip")
	writeZip(t, zp, map[string]string{
		"KNcloud/KNcloud.exe":         "MZnew",
		"KNcloud/bin/geoip.dat":       "geo-new",
		"KNcloud/bin/sub/extra.txt":   "extra",
		"KNcloud/configs/config.json": "MUST NOT BE INSTALLED",
	})
	staged := filepath.Join(dir, "staged")
	files, err := extractUpdateZip(zp, staged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(staged, "KNcloud.exe")); err != nil {
		t.Fatalf("top-level dir not stripped: %v (files %v)", err, files)
	}

	root := filepath.Join(dir, "app")
	os.MkdirAll(filepath.Join(root, "bin"), 0755)
	os.MkdirAll(filepath.Join(root, "configs"), 0755)
	exe := filepath.Join(root, "KNcloud.exe")
	os.WriteFile(exe, []byte("MZold"), 0644)
	os.WriteFile(filepath.Join(root, "bin", "geoip.dat"), []byte("geo-old"), 0644)
	os.WriteFile(filepath.Join(root, "configs", "config.json"), []byte("user-config"), 0644)

	if err := installUpdateFiles(staged, files, root, exe); err != nil {
		t.Fatal(err)
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	if read(exe) != "MZnew" || read(exe+".old") != "MZold" {
		t.Fatalf("exe not replaced: %q / %q", read(exe), read(exe+".old"))
	}
	if read(filepath.Join(root, "bin", "geoip.dat")) != "geo-new" || read(filepath.Join(root, "bin", "sub", "extra.txt")) != "extra" {
		t.Fatal("bin not updated")
	}
	if read(filepath.Join(root, "configs", "config.json")) != "user-config" {
		t.Fatal("configs touched by update")
	}
}

func TestInstallUpdateRollsBack(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged")
	os.MkdirAll(filepath.Join(staged, "bin"), 0755)
	os.WriteFile(filepath.Join(staged, "KNcloud.exe"), []byte("MZnew"), 0644)
	os.WriteFile(filepath.Join(staged, "bin", "a.dat"), []byte("a-new"), 0644)
	root := filepath.Join(dir, "app")
	os.MkdirAll(filepath.Join(root, "bin"), 0755)
	exe := filepath.Join(root, "KNcloud.exe")
	os.WriteFile(exe, []byte("MZold"), 0644)
	os.WriteFile(filepath.Join(root, "bin", "a.dat"), []byte("a-old"), 0644)

	// bin/missing.dat 在暂存目录里不存在 → 写入失败 → 全部回滚
	err := installUpdateFiles(staged, []string{"KNcloud.exe", "bin/a.dat", "bin/missing.dat"}, root, exe)
	if err == nil {
		t.Fatal("want error")
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	if read(exe) != "MZold" || read(filepath.Join(root, "bin", "a.dat")) != "a-old" {
		t.Fatalf("not rolled back: exe=%q a=%q", read(exe), read(filepath.Join(root, "bin", "a.dat")))
	}
	if _, err := os.Stat(exe + ".old"); err == nil {
		t.Fatal(".old left behind after rollback")
	}

	// 新 exe 不是 PE：拒绝安装，什么都不动
	os.WriteFile(filepath.Join(staged, "KNcloud.exe"), []byte("not-pe"), 0644)
	if err := installUpdateFiles(staged, []string{"KNcloud.exe"}, root, exe); err == nil {
		t.Fatal("invalid exe accepted")
	}
	if read(exe) != "MZold" {
		t.Fatal("exe changed although new exe is invalid")
	}
}
