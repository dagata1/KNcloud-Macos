//go:build darwin

package main

// tunhelper_darwin.go —— macOS TUN 的特权助手。
//
// 为什么需要它：创建 utun、改路由表、改系统 DNS 都需要 root，而 GUI 程序（Wails/WebKit）
// 不应整体以 root 运行。方案（最简单且稳健）：
//
//   - 首次开启 TUN 时，用 osascript「do shell script … with administrator privileges」
//     以 root 拉起本程序自身的另一个进程：KNcloud --tun-helper <socket> <uid> <ppid>
//     （系统弹出标准的管理员密码框；已有免密 sudo 时直接走 sudo -n，CI 即如此）；
//   - 助手只做特权操作：创建 utun（通过 SCM_RIGHTS 把文件描述符交给主程序）、
//     增删路由（/sbin/route）、设置/还原各网络服务的 DNS（networksetup）、清 DNS 缓存；
//   - gVisor 协议栈、转发、Xray 内核全部仍在普通权限的主程序里运行，与 Windows 共用同一套代码；
//   - 助手只接受同一用户（LOCAL_PEERCRED 校验 uid）的连接，主程序退出（父进程消失）后
//     助手自动撤销自己加过的路由、还原 DNS 并退出。utun 的描述符只在主程序手里，
//     主程序崩溃时 utun 与其上的路由由内核自动回收。

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const tunHelperProtoVersion = 1

type helperReq struct {
	Op      string   `json:"op"`
	MTU     int      `json:"mtu,omitempty"`
	Dst     string   `json:"dst,omitempty"` // CIDR
	Gateway string   `json:"gw,omitempty"`
	Iface   string   `json:"iface,omitempty"`
	Scope   string   `json:"scope,omitempty"` // 非空：-ifscope 该接口（只对绑定了该接口的 socket 生效的作用域路由）
	V6      bool     `json:"v6,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type helperResp struct {
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
	Code    string `json:"code,omitempty"` // exists | notfound
	Name    string `json:"name,omitempty"`
	Index   int    `json:"index,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
	Bool    bool   `json:"bool,omitempty"`
	Version int    `json:"version,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

// ------------------------- 帧格式：4 字节长度 + JSON（可附带 SCM_RIGHTS） -------------------------

func writeHelperFrame(c *net.UnixConn, v any, fd int) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	if fd >= 0 {
		n, _, err := c.WriteMsgUnix(b, unix.UnixRights(fd), nil)
		if err != nil {
			return err
		}
		if n < len(b) {
			_, err = c.Write(b[n:])
		}
		return err
	}
	_, err = c.Write(b)
	return err
}

func readHelperFrame(c *net.UnixConn, v any) (fds []int, err error) {
	oob := make([]byte, unix.CmsgSpace(4*4))
	readFull := func(buf []byte) error {
		got := 0
		for got < len(buf) {
			n, oobn, _, _, err := c.ReadMsgUnix(buf[got:], oob)
			if oobn > 0 {
				if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
					for _, m := range msgs {
						if r, perr := unix.ParseUnixRights(&m); perr == nil {
							fds = append(fds, r...)
						}
					}
				}
			}
			got += n
			if err != nil {
				if got == len(buf) {
					return nil
				}
				return err
			}
			if n == 0 && oobn == 0 {
				return io.ErrUnexpectedEOF
			}
		}
		return nil
	}
	var hdr [4]byte
	if err := readFull(hdr[:]); err != nil {
		return fds, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > 1<<20 {
		return fds, fmt.Errorf("helper frame too large (%d)", size)
	}
	body := make([]byte, size)
	if err := readFull(body); err != nil {
		return fds, err
	}
	return fds, json.Unmarshal(body, v)
}

// ------------------------- 助手（root 进程） -------------------------

type helperRoute struct {
	Dst, Gateway, Iface, Scope string
	V6                         bool
}

type tunHelperServer struct {
	uid int
	mu  sync.Mutex
	// routes 本助手亲自加成功的路由。已存在（File exists）的路由不记账，
	// 删除请求只作用于记账内的路由 —— 绝不会误删用户或其它 VPN 的同名路由。
	routes map[helperRoute]bool
	// dnsSaved 被改写前各网络服务的 DNS（"Empty" 表示原本走 DHCP）；nil 表示未改写。
	dnsSaved map[string][]string
	logf     func(string, ...any)
}

func newTunHelperServer(uid int) *tunHelperServer {
	return &tunHelperServer{uid: uid, routes: map[helperRoute]bool{}, logf: log.Printf}
}

// runTunHelper 入口：KNcloud --tun-helper <socket> <uid> <ppid>
func runTunHelper(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: --tun-helper <socket> <uid> <ppid>")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "--tun-helper must run as root")
		return 2
	}
	sock := args[0]
	uid, err1 := strconv.Atoi(args[1])
	ppid, err2 := strconv.Atoi(args[2])
	if err1 != nil || err2 != nil || ppid <= 1 {
		fmt.Fprintln(os.Stderr, "bad uid/ppid")
		return 2
	}
	if lf, err := os.OpenFile(filepath.Join(filepath.Dir(sock), "tunhelper.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
		_ = lf.Chown(uid, -1)
		log.SetOutput(lf)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	_ = os.Remove(sock)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		log.Printf("listen %s: %v", sock, err)
		return 1
	}
	_ = os.Chown(sock, uid, -1)
	_ = os.Chmod(sock, 0600)
	s := newTunHelperServer(uid)
	log.Printf("KNcloud TUN helper started pid=%d uid=%d ppid=%d", os.Getpid(), uid, ppid)

	quit := func(reason string) {
		log.Printf("exiting: %s", reason)
		s.cleanup()
		l.Close()
		_ = os.Remove(sock)
		os.Exit(0)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() { quit(fmt.Sprintf("signal %v", <-sigs)) }()
	go func() {
		for {
			time.Sleep(time.Second)
			if err := unix.Kill(ppid, 0); errors.Is(err, unix.ESRCH) {
				quit("parent process gone")
			}
		}
	}()
	s.serve(l, func() { quit("quit requested") })
	return 0
}

// serve 接受连接（每个连接一个协程，操作在 s.mu 下串行执行）。
func (s *tunHelperServer) serve(l *net.UnixListener, onQuit func()) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		if !s.peerAllowed(c) {
			s.logf("rejected connection from foreign uid")
			c.Close()
			continue
		}
		go s.handleConn(c, onQuit)
	}
}

func (s *tunHelperServer) peerAllowed(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err == nil && (int(cred.Uid) == s.uid || cred.Uid == 0) {
			ok = true
		}
	})
	return ok
}

func (s *tunHelperServer) handleConn(c *net.UnixConn, onQuit func()) {
	defer c.Close()
	for {
		var req helperReq
		if _, err := readHelperFrame(c, &req); err != nil {
			return
		}
		resp, fd := s.handle(req)
		err := writeHelperFrame(c, resp, fd)
		if fd >= 0 {
			unix.Close(fd) // 描述符已交给主程序：助手不持有 utun
		}
		if err != nil {
			return
		}
		if req.Op == "quit" && onQuit != nil {
			onQuit()
			return
		}
	}
}

var ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9]{1,15}$`)

func (s *tunHelperServer) handle(req helperReq) (helperResp, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(err error) (helperResp, int) {
		s.logf("%s failed: %v", req.Op, err)
		return helperResp{Err: err.Error()}, -1
	}
	switch req.Op {
	case "hello":
		return helperResp{OK: true, Version: tunHelperProtoVersion, PID: os.Getpid()}, -1
	case "open_utun":
		fd, name, mtu, err := s.openUtun(req.MTU)
		if err != nil {
			return fail(err)
		}
		idx := 0
		if ifc, err := net.InterfaceByName(name); err == nil {
			idx = ifc.Index
		}
		s.logf("opened %s (index %d, mtu %d)", name, idx, mtu)
		return helperResp{OK: true, Name: name, Index: idx, MTU: mtu}, fd
	case "route_add", "route_del":
		r, err := validateHelperRoute(req)
		if err != nil {
			return fail(err)
		}
		if req.Op == "route_add" {
			code, err := s.routeAdd(r)
			if err != nil {
				return fail(err)
			}
			return helperResp{OK: code == "", Code: code}, -1
		}
		code, err := s.routeDel(r)
		if err != nil {
			return fail(err)
		}
		return helperResp{OK: code == "", Code: code}, -1
	case "route_clear":
		n, failed := s.clearRoutes(req.Iface)
		if failed > 0 {
			return helperResp{Err: fmt.Sprintf("%d route(s) could not be removed", failed), Index: n}, -1
		}
		return helperResp{OK: true, Index: n}, -1
	case "dns_set":
		for _, d := range req.DNS {
			if net.ParseIP(d) == nil {
				return fail(fmt.Errorf("bad DNS address %q", d))
			}
		}
		if err := s.setDNS(req.DNS); err != nil {
			return fail(err)
		}
		return helperResp{OK: true}, -1
	case "dns_restore":
		s.restoreDNS()
		return helperResp{OK: true}, -1
	case "dns_get":
		return helperResp{OK: true, Bool: s.dnsSaved != nil}, -1
	case "flush_dns":
		flushDNSCachesAsRoot()
		return helperResp{OK: true}, -1
	case "cleanup", "quit":
		s.cleanupLocked()
		return helperResp{OK: true}, -1
	}
	return fail(fmt.Errorf("unknown op %q", req.Op))
}

func validateHelperRoute(req helperReq) (helperRoute, error) {
	ip, n, err := net.ParseCIDR(req.Dst)
	if err != nil {
		return helperRoute{}, fmt.Errorf("bad destination %q", req.Dst)
	}
	if (ip.To4() == nil) != req.V6 {
		return helperRoute{}, fmt.Errorf("address family mismatch for %q", req.Dst)
	}
	r := helperRoute{Dst: n.String(), V6: req.V6}
	switch {
	case req.Iface != "":
		if !ifaceNameRe.MatchString(req.Iface) {
			return helperRoute{}, fmt.Errorf("bad interface %q", req.Iface)
		}
		r.Iface = req.Iface
	case req.Gateway != "":
		if net.ParseIP(req.Gateway) == nil {
			return helperRoute{}, fmt.Errorf("bad gateway %q", req.Gateway)
		}
		r.Gateway = req.Gateway
	default:
		return helperRoute{}, errors.New("route needs a gateway or an interface")
	}
	if req.Scope != "" {
		if !ifaceNameRe.MatchString(req.Scope) {
			return helperRoute{}, fmt.Errorf("bad scope interface %q", req.Scope)
		}
		r.Scope = req.Scope
	}
	return r, nil
}

func routeCmdArgs(verb string, r helperRoute) []string {
	args := []string{"-n", verb}
	if r.V6 {
		args = append(args, "-inet6")
	}
	args = append(args, "-net", r.Dst)
	if r.Iface != "" {
		args = append(args, "-interface", r.Iface)
	} else {
		args = append(args, r.Gateway)
	}
	if r.Scope != "" {
		args = append(args, "-ifscope", r.Scope)
	}
	return args
}

func runRouteCmd(verb string, r helperRoute) (string, error) {
	out, err := exec.Command("/sbin/route", routeCmdArgs(verb, r)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (s *tunHelperServer) routeAdd(r helperRoute) (string, error) {
	if s.routes[r] {
		return "exists", nil
	}
	out, err := runRouteCmd("add", r)
	if err != nil || strings.Contains(out, "File exists") {
		if strings.Contains(out, "File exists") {
			return "exists", nil // 别人的同名路由：不记账，日后也不会删
		}
		return "", fmt.Errorf("route add %s: %v: %s", r.Dst, err, out)
	}
	s.routes[r] = true
	return "", nil
}

func (s *tunHelperServer) routeDel(r helperRoute) (string, error) {
	if !s.routes[r] {
		return "notfound", nil
	}
	out, err := runRouteCmd("delete", r)
	if err != nil || strings.Contains(out, "not in table") {
		if strings.Contains(out, "not in table") {
			delete(s.routes, r)
			return "notfound", nil
		}
		return "", fmt.Errorf("route delete %s: %v: %s", r.Dst, err, out)
	}
	delete(s.routes, r)
	return "", nil
}

// clearRoutes 删除记账内的路由（iface 非空时只删该网卡上的）。
func (s *tunHelperServer) clearRoutes(iface string) (removed, failed int) {
	for r := range s.routes {
		if iface != "" && r.Iface != iface {
			continue
		}
		if _, err := s.routeDel(r); err != nil {
			s.logf("%v", err)
			failed++
			continue
		}
		removed++
	}
	return removed, failed
}

func (s *tunHelperServer) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
}

func (s *tunHelperServer) cleanupLocked() {
	n, failed := s.clearRoutes("")
	s.restoreDNS()
	if n > 0 || failed > 0 {
		s.logf("cleanup: removed %d route(s), %d failed", n, failed)
	}
}

// ------------------------- DNS（networksetup） -------------------------

// networkServices 列出启用中的网络服务（networksetup -listallnetworkservices，跳过首行说明与 * 开头的停用项）。
func networkServices() ([]string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 && strings.Contains(line, "asterisk") {
			continue
		}
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

func getServiceDNS(svc string) []string {
	out, err := exec.Command("/usr/sbin/networksetup", "-getdnsservers", svc).Output()
	if err != nil {
		return []string{"Empty"}
	}
	var ips []string
	for _, l := range strings.Split(string(out), "\n") {
		if ip := net.ParseIP(strings.TrimSpace(l)); ip != nil {
			ips = append(ips, ip.String())
		}
	}
	if len(ips) == 0 {
		return []string{"Empty"}
	}
	return ips
}

func (s *tunHelperServer) setDNS(servers []string) error {
	svcs, err := networkServices()
	if err != nil {
		return fmt.Errorf("list network services: %v", err)
	}
	if s.dnsSaved == nil {
		s.dnsSaved = map[string][]string{}
	}
	var firstErr error
	okCount := 0
	for _, svc := range svcs {
		if _, saved := s.dnsSaved[svc]; !saved {
			s.dnsSaved[svc] = getServiceDNS(svc)
		}
		args := append([]string{"-setdnsservers", svc}, servers...)
		if out, err := exec.Command("/usr/sbin/networksetup", args...).CombinedOutput(); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("set DNS on %q: %v: %s", svc, err, strings.TrimSpace(string(out)))
			}
			continue
		}
		okCount++
	}
	if okCount == 0 && firstErr != nil {
		return firstErr
	}
	flushDNSCachesAsRoot()
	return nil
}

func (s *tunHelperServer) restoreDNS() {
	if s.dnsSaved == nil {
		return
	}
	for svc, old := range s.dnsSaved {
		args := append([]string{"-setdnsservers", svc}, old...)
		if out, err := exec.Command("/usr/sbin/networksetup", args...).CombinedOutput(); err != nil {
			s.logf("restore DNS on %q: %v: %s", svc, err, strings.TrimSpace(string(out)))
		}
	}
	s.dnsSaved = nil
	flushDNSCachesAsRoot()
}

func flushDNSCachesAsRoot() {
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

// ------------------------- 主程序侧客户端 -------------------------

type tunHelperClient struct {
	mu   sync.Mutex
	conn *net.UnixConn
	// sockOverride / launchOverride 供测试注入（进程内助手）。
	sockOverride string
}

var tunHelper = &tunHelperClient{}

func (c *tunHelperClient) sockPath() string {
	if c.sockOverride != "" {
		return c.sockOverride
	}
	dir, err := appConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "tunhelper.sock")
}

func (c *tunHelperClient) dial() (*net.UnixConn, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.sockPath(), Net: "unix"})
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeHelperFrame(conn, helperReq{Op: "hello"}, -1); err != nil {
		conn.Close()
		return nil, err
	}
	var resp helperResp
	if _, err := readHelperFrame(conn, &resp); err != nil || !resp.OK || resp.Version != tunHelperProtoVersion {
		conn.Close()
		if err == nil {
			err = fmt.Errorf("helper protocol mismatch (version %d)", resp.Version)
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// connected 助手是否已连上（不会触发授权弹窗）。
func (c *tunHelperClient) connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// ensure 连上特权助手；没有在运行时拉起它（可能弹出管理员授权框，最多等 2 分钟）。
func (c *tunHelperClient) ensure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	if conn, err := c.dial(); err == nil {
		c.conn = conn
		return nil
	}
	if err := launchTunHelper(c.sockPath()); err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := c.dial()
		if err == nil {
			c.conn = conn
			return nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("TUN helper did not start: %v", lastErr)
}

// call 发送一个请求并取回应答（以及随应答附带的文件描述符）。
func (c *tunHelperClient) call(req helperReq) (helperResp, []int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return helperResp{}, nil, errors.New("TUN helper is not running")
	}
	_ = c.conn.SetDeadline(time.Now().Add(60 * time.Second))
	defer func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}()
	if err := writeHelperFrame(c.conn, req, -1); err != nil {
		c.conn.Close()
		c.conn = nil
		return helperResp{}, nil, fmt.Errorf("TUN helper connection lost: %v", err)
	}
	var resp helperResp
	fds, err := readHelperFrame(c.conn, &resp)
	if err != nil {
		for _, fd := range fds {
			unix.Close(fd)
		}
		c.conn.Close()
		c.conn = nil
		return helperResp{}, nil, fmt.Errorf("TUN helper connection lost: %v", err)
	}
	return resp, fds, nil
}

// do 调用并把失败应答转成 error。
func (c *tunHelperClient) do(req helperReq) (helperResp, error) {
	resp, fds, err := c.call(req)
	for _, fd := range fds {
		unix.Close(fd)
	}
	if err != nil {
		return resp, err
	}
	if !resp.OK && resp.Code == "" {
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

// close 断开与助手的连接（助手在父进程退出后自行清理并退出）。
func (c *tunHelperClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// launchTunHelper 以 root 拉起助手：已是 root 直接启动；有免密 sudo 用 sudo -n；
// 否则通过 osascript 弹出系统管理员授权框。
func launchTunHelper(sock string) error {
	exe, err := currentExecutablePath()
	if err != nil {
		return err
	}
	_ = os.Remove(sock)
	args := []string{"--tun-helper", sock, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getpid())}
	if os.Geteuid() == 0 {
		cmd := exec.Command(exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		return cmd.Start()
	}
	if exec.Command("/usr/bin/sudo", "-n", "/usr/bin/true").Run() == nil {
		cmd := exec.Command("/usr/bin/sudo", append([]string{"-n", exe}, args...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err == nil {
			go cmd.Wait()
			return nil
		}
	}
	shell := shellQuote(exe)
	for _, a := range args {
		shell += " " + shellQuote(a)
	}
	shell += " >/dev/null 2>&1 &"
	script := fmt.Sprintf("do shell script %s with prompt %s with administrator privileges",
		appleScriptString(shell), appleScriptString("KNcloud 需要管理员权限来开启 TUN 模式（创建虚拟网卡、修改路由与 DNS）。"))
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "-128") || strings.Contains(strings.ToLower(msg), "cancel") {
			return errors.New("已取消管理员授权，TUN 模式未开启")
		}
		return fmt.Errorf("administrator authorization failed: %v: %s", err, msg)
	}
	return nil
}

// shellQuote 单引号包裹（POSIX sh）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// appleScriptString AppleScript 字符串字面量（转义反斜杠与双引号）。
func appleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
