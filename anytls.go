package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// ------------------------- AnyTLS 协议桥 -------------------------
//
// Xray-core 没有 AnyTLS 出站（VLESS/VMess/Trojan/Shadowsocks 之外的协议一律不支持，
// 上游最新版同样没有），所以 AnyTLS 节点没法像其它节点那样直接生成 Xray 出站。
//
// 这里改成「协议桥」：用内置 sing-box 起一个只监听 127.0.0.1 的 mixed 入站
// （SOCKS5 + HTTP），出站固定是 AnyTLS；Xray 侧把这个本地端口当成 socks 出站，
// 于是链路变成
//
//	应用 → Xray(SOCKS/HTTP 入站 + 路由分流) → sing-box 桥 → AnyTLS 服务器
//
// Xray 仍是唯一的分流 / 统计 / 系统代理 / TUN 出口大脑，
// TUN 模式的 gvisor 转发照旧把流量交给 Xray SOCKS，桥对上层完全透明。
//
// 另一个要点：桥里的 sing-box 是独立进程，不认本程序的 TUN 分流路由，
// 因此必须在 Go 侧先把服务器地址解析成 IP 写进配置（配合写好的 /32 防回环路由
// 从物理网卡出网）。若交给桥自己解析，TUN 模式下系统 DNS 已被劫持进 TUN，
// 解析请求会绕回 Xray → 桥 → 再解析，形成死锁。

// anyTLSBridge 是一个运行中的 AnyTLS 桥进程。
type anyTLSBridge struct {
	cmd     *exec.Cmd
	addr    string // 127.0.0.1:port，供 Xray socks 出站连接
	done    chan struct{}
	job     windows.Handle
	cfgPath string
	logPath string
	logFile *os.File
}

// needsSingBoxBridge 该协议是否必须走 sing-box 协议桥（Xray 内核无法直连）。
func needsSingBoxBridge(protocol string) bool {
	return protocol == "AnyTLS"
}

// buildAnyTLSBridgeConfig 生成 sing-box 桥配置：本地 mixed 入站 + AnyTLS 出站。
// serverIP 传预解析出的地址（避免 TUN 模式 DNS 回环），域名只用于 TLS SNI。
func buildAnyTLSBridgeConfig(node NodeItem, port int, serverIP string) (string, error) {
	if node.UUID == "" {
		return "", fmt.Errorf("AnyTLS node missing password")
	}
	if node.Port <= 0 || node.Port > 65535 {
		return "", fmt.Errorf("AnyTLS node has invalid port: %d", node.Port)
	}
	if serverIP == "" {
		serverIP = node.Address
	}

	tlsObj := map[string]interface{}{
		"enabled":  true,
		"insecure": node.Insecure,
	}
	// 服务器写 IP 时 SNI 必须显式给出，否则 TLS 校验会拿 IP 去比对证书
	if sni := firstNonEmpty(node.SNI, node.Address); sni != "" && sni != serverIP {
		tlsObj["server_name"] = sni
	}
	// AnyTLS 常常架在 CDN 后面，TLS 指纹被拦的概率不低，默认套浏览器指纹
	if fp := firstNonEmpty(node.FP, "chrome"); fp != "" {
		tlsObj["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{"level": "warning"},
		// 两套 DNS 各司其职：
		//   dns-cn  直连国内 DNS，只给服务器地址解析用（走代理解析会自噬成死循环）
		//   dns-fw  经隧道解析 Xray 转过来的目标域名；TUN 模式下系统 DNS 已被劫持，
		//           桥必须自己有解析能力，否则第一条连接就是 NXDOMAIN
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				// 不能 detour:"direct"：空 direct 出站在新版里会被判为
				// "empty direct outbound makes no sense" 而拒绝启动，不写 detour 即直连
				{"type": "udp", "tag": "dns-cn", "server": "223.5.5.5"},
				{"type": "udp", "tag": "dns-fw", "server": "1.1.1.1", "detour": "proxy"},
				{"type": "udp", "tag": "dns-fw2", "server": "8.8.8.8", "detour": "proxy"},
			},
			"final": "dns-fw",
		},
		"inbounds": []map[string]interface{}{{
			"type":        "mixed",
			"tag":         "bridge-in",
			"listen":      "127.0.0.1",
			"listen_port": port,
		}},
		"outbounds": []map[string]interface{}{
			{
				"type":        "anytls",
				"tag":         "proxy",
				"server":      serverIP,
				"server_port": node.Port,
				"password":    node.UUID,
				"tls":         tlsObj,
			},
		},
		// 桥只服务这一条 AnyTLS 链路，进来的流量全部交给 AnyTLS 出站
		// default_domain_resolver 兜住所有未显式指定解析来源的出站（1.12 起缺失即致命），
		// 指向直连那份，免得服务器地址解析绕回隧道自噬
		"route": map[string]interface{}{"final": "proxy", "default_domain_resolver": "dns-cn"},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// freeLocalPort 取一个当前空闲的回环端口。
func freeLocalPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// resolveNodeServerIP 预解析节点服务器地址，供桥使用（TUN 模式下防 DNS 回环）。
func resolveNodeServerIP(node NodeItem) string {
	// 走与 TUN /32 防回环路由同一套解析与缓存，保证桥和路由表指向同一个 IP
	ips := lookupNodeIPv4sCached(node.Address)
	if len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

// startAnyTLSBridge 拉起 AnyTLS 协议桥，返回可用实例；调用方负责 Stop。
func startAnyTLSBridge(node NodeItem) (*anyTLSBridge, error) {
	exePath, err := ensureSingBoxBin()
	if err != nil {
		return nil, fmt.Errorf("failed to unpack sing-box binary: %w", err)
	}
	cfgDir, err := appConfigDir()
	if err != nil {
		return nil, err
	}

	// 端口是「探测空闲后立刻交给 sing-box」的方式，理论上存在被别人抢占的窗口，
	// 撞上时换端口重试；配置类错误直接失败，不浪费三秒
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		port, err := freeLocalPort()
		if err != nil {
			return nil, err
		}
		cfgJSON, err := buildAnyTLSBridgeConfig(node, port, resolveNodeServerIP(node))
		if err != nil {
			return nil, err
		}
		// 配置与日志都按端口命名：并发测速会同时起多个桥，
		// 共用一个文件会互相覆盖配置（端口错乱）或截断日志
		cfgPath := filepath.Join(cfgDir, fmt.Sprintf("sing-box-anytls-%d.json", port))
		if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
			return nil, err
		}

		cmd := exec.Command(exePath, "run", "-c", cfgPath)
		cmd.SysProcAttr = hiddenProc()
		logPath := filepath.Join(cfgDir, fmt.Sprintf("sing-box-anytls-%d.log", port))
		var logFile *os.File
		if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
			cmd.Stdout = lf
			cmd.Stderr = lf
			logFile = lf
		}
		if err := cmd.Start(); err != nil {
			if logFile != nil {
				logFile.Close()
			}
			return nil, fmt.Errorf("failed to start sing-box bridge: %w", err)
		}

		b := &anyTLSBridge{
			cmd:     cmd,
			addr:    "127.0.0.1:" + strconv.Itoa(port),
			done:    make(chan struct{}),
			cfgPath: cfgPath,
			logPath: logPath,
		}
		// KILL_ON_JOB_CLOSE：本进程被强杀时系统自动带走桥进程，
		// 不留一个还在连服务器的孤儿 sing-box
		if job, jerr := createKillOnCloseJob(); jerr == nil {
			if ph, oerr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); oerr == nil {
				if aerr := windows.AssignProcessToJobObject(job, ph); aerr == nil {
					b.job = job
				} else {
					windows.CloseHandle(job)
				}
				windows.CloseHandle(ph)
			} else {
				windows.CloseHandle(job)
			}
		}
		go func() {
			cmd.Wait()
			close(b.done)
		}()

		err = b.waitReady()
		if err == nil {
			b.logFile = logFile
			return b, nil
		}
		tail := tailOfFile(b.logPath, 300)
		// 只有端口被抢占才值得换端口重试；
		// sing-box 报配置致命错时重试多少次都是同样的结果
		if !portConflictLog(tail) {
			b.Stop()
			return nil, fmt.Errorf("%w: %s", err, tail)
		}
		lastErr = fmt.Errorf("%w: %s", err, tail)
		b.Stop()
	}
	return nil, lastErr
}

// portConflictLog 判断 sing-box 日志是不是"本地端口被占"，
// 用于区分可重试的端口竞争与不可重试的配置错误。
func portConflictLog(tail string) bool {
	l := strings.ToLower(tail)
	return strings.Contains(l, "address already in use") ||
		strings.Contains(l, "only one usage of each socket address") ||
		strings.Contains(l, "bind: address already in use")
}

// waitReady 等待桥的本地入站可连接，同时能识别进程秒退（如端口被占）。
func (b *anyTLSBridge) waitReady() error {
	// 桥启动失败基本都是配置问题（参数不对 / sing-box 版本太老），
	// 重试只会得到同样的错误，端口冲突之外不必重试
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-b.done:
			return fmt.Errorf("sing-box bridge exited immediately")
		default:
		}
		conn, err := net.DialTimeout("tcp", b.addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bridge local port %s not ready", b.addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Stop 终止桥进程并回收资源（可重复调用）。
func (b *anyTLSBridge) Stop() {
	if b == nil || b.cmd == nil {
		return
	}
	if b.cmd.Process != nil {
		b.cmd.Process.Kill()
	}
	// 桥已被 Kill，Wait 应当立即返回；留 3 秒兜底避免 Stop 卡死调用方
	select {
	case <-b.done:
	case <-time.After(3 * time.Second):
	}
	b.cmd = nil
	if b.job != 0 {
		windows.CloseHandle(b.job)
		b.job = 0
	}
	if b.logFile != nil {
		b.logFile.Close()
		b.logFile = nil
	}
	// 配置里含节点密码，用完即删；日志留在原处以备排查启动失败
	if b.cfgPath != "" {
		os.Remove(b.cfgPath)
		b.cfgPath = ""
	}
}

// tailOfFile 读文件尾部若干字节，用于把子进程报错翻译成人话。
func tailOfFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}
