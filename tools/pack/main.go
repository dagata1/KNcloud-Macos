// Command pack 把 wails 构建出的 exe 和运行资源组装成绿色版文件夹并打成 zip：
//
//	<out>/KNcloud/KNcloud.exe
//	<out>/KNcloud/bin/{geoip.dat,geosite.dat,wintun.dll,badvpn-tun2socks.exe,许可文件}
//	<out>/KNcloud-WIN-<version>.zip
//
// 用法（在项目根目录）：go run ./tools/pack -exe build/bin/KNcloud-WIN.exe -out dist -version v1.3.23
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	exe := flag.String("exe", "build/bin/KNcloud-WIN.exe", "built executable")
	out := flag.String("out", "dist", "output directory")
	version := flag.String("version", "dev", "version used in the zip name")
	flag.Parse()
	if err := run(*exe, *out, *version); err != nil {
		fmt.Fprintln(os.Stderr, "pack:", err)
		os.Exit(1)
	}
}

func run(exe, out, version string) error {
	root := filepath.Join(out, "KNcloud")
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	files := [][2]string{
		{exe, "KNcloud.exe"},
		{"geo/geoip.dat", "bin/geoip.dat"},
		{"geo/geosite.dat", "bin/geosite.dat"},
		{"cores/wintun.dll", "bin/wintun.dll"},
		{"cores/wintun-LICENSE.txt", "bin/wintun-LICENSE.txt"},
		{"cores/native/bin/badvpn-tun2socks.exe", "bin/badvpn-tun2socks.exe"},
		{"cores/native/BADVPN-COPYING.txt", "bin/BADVPN-COPYING.txt"},
	}
	for _, f := range files {
		if err := copyFile(f[0], filepath.Join(root, filepath.FromSlash(f[1]))); err != nil {
			return err
		}
	}
	zipPath := filepath.Join(out, "KNcloud-WIN-"+version+".zip")
	return zipDir(root, "KNcloud", zipPath)
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	o, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(o, in); err != nil {
		o.Close()
		return err
	}
	return o.Close()
}

func zipDir(dir, prefix, zipPath string) error {
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(filepath.Join(prefix, rel))
		h.Method = zip.Deflate
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
