package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var errNativeTunUnavailable = errors.New("native SSTap tun2socks helper is not installed")

const (
	nativeSSTapIface     = "SSTAP 1"
	nativeSSTapComponent = "tap0901"
	nativeSSTapIP        = "10.198.75.60"
	nativeSSTapNetmask   = "255.255.255.0"
	nativeSSTapRouterIP  = "10.198.75.61"
	nativeSSTapNetwork   = "10.198.75.0"
)

func nativeTunPath() string {
	if p, err := findResource("badvpn-tun2socks.exe", filepath.Join("cores", "native", "bin")); err == nil {
		return p
	}
	if d := exeDir(); d != "" {
		return filepath.Join(d, "cores", "native", "bin", "badvpn-tun2socks.exe")
	}
	return ""
}

func nativeTunIfaceIndex() (uint32, error) {
	iface, err := net.InterfaceByName(nativeSSTapIface)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Index), nil
}

func (a *App) startNativeTun(node NodeItem) error {
	binary := nativeTunPath()
	if binary == "" {
		return errNativeTunUnavailable
	}
	if st, err := os.Stat(binary); err != nil || st.IsDir() {
		return errNativeTunUnavailable
	}
	idx, err := nativeTunIfaceIndex()
	if err != nil {
		return fmt.Errorf("SSTap TAP adapter %q not found: %w", nativeSSTapIface, err)
	}

	cmd := exec.Command(binary,
		"--tundev", nativeSSTapComponent+":"+nativeSSTapIface+":"+nativeSSTapIP+":"+nativeSSTapNetwork+":"+nativeSSTapNetmask,
		"--netif-ipaddr", nativeSSTapRouterIP,
		"--netif-netmask", nativeSSTapNetmask,
		"--socks-server-addr", fmt.Sprintf("127.0.0.1:%d", a.settings.SocksPort),
		"--socks5-udp",
		"--loglevel", "warning",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow | syscall.CREATE_NEW_PROCESS_GROUP}
	logDir, _ := appLogDir()
	if logDir != "" {
		if f, e := os.OpenFile(filepath.Join(logDir, "sstap-tun2socks.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); e == nil {
			cmd.Stdout, cmd.Stderr = f, f
		}
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start native SSTap tun2socks: %w", err)
	}
	a.nativeTunCmd = cmd
	a.nativeTunDone = make(chan struct{})
	done := a.nativeTunDone
	go func() {
		err := cmd.Wait()
		close(done)
		a.mu.Lock()
		if a.nativeTunCmd == cmd {
			a.nativeTunCmd = nil
			a.nativeTunDone = nil
			if a.tunRunning {
				// 引擎意外退出：路由还指向一张没人转发的网卡。完整软停（撤路由、恢复内核配置），
				// 不能只把 tunRunning 置假 —— 那会留下几千条路由和错误的界面状态。
				a.addLogInternal("warn", fmt.Sprintf("native SSTap tun2socks exited: %v; stopping TUN", err))
				a.tunSoftStopLocked()
				tray.requestRebuild()
			}
		}
		a.mu.Unlock()
	}()
	a.tunIfaceIdx = idx
	time.Sleep(120 * time.Millisecond)
	select {
	case <-done:
		a.nativeTunCmd = nil
		return fmt.Errorf("native SSTap tun2socks exited during startup")
	default:
		return nil
	}
}

func (a *App) stopNativeTun() {
	cmd := a.nativeTunCmd
	done := a.nativeTunDone
	a.nativeTunCmd, a.nativeTunDone = nil, nil
	if cmd == nil {
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
}

func (a *App) nativeTunRunning() bool { return a.nativeTunCmd != nil }
