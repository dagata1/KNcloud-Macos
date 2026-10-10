// Package portpick 为内核的本地 SOCKS / HTTP 入站挑选可用端口：配置的端口被别的程序
// 占用（或被系统保留）时，自动换到一个空闲端口，而不是让内核起不来。
// 纯逻辑 + 标准库监听探测，不依赖 Windows API，可在 Linux 上跑单测；调用方在主包 core.go。
package portpick

import (
	"net"
	"strconv"
)

// SearchSpan 从原端口往上最多找多少个端口；都不行再让系统分配。
const SearchSpan = 200

// Busy 报告某端口当前能否被本程序监听（true = 不能用）。
type Busy func(port int) bool

// ListenBusy 用真实监听探测 host:port 是否可用（TCP）。host 为空按 127.0.0.1。
func ListenBusy(host string) Busy {
	if host == "" {
		host = "127.0.0.1"
	}
	return func(port int) bool {
		if port <= 0 || port > 65535 {
			return true
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return true
		}
		ln.Close()
		return false
	}
}

// SystemAssign 让系统在 host 上分配一个空闲 TCP 端口（失败返回 0）。
func SystemAssign(host string) func() int {
	if host == "" {
		host = "127.0.0.1"
	}
	return func() int {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return 0
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
}

// Pick 返回可用端口：want 可用且不在 avoid 里就用 want；否则从 want+1 往上找
// （最多 SearchSpan 个、不超过 65535），再不行用 sysAssign 让系统分配。全部失败返回 0。
func Pick(want int, avoid map[int]bool, busy Busy, sysAssign func() int) int {
	ok := func(p int) bool { return p > 0 && p <= 65535 && !avoid[p] && !busy(p) }
	if ok(want) {
		return want
	}
	start := want + 1
	if start < 1024 {
		start = 1024
	}
	for p := start; p < start+SearchSpan && p <= 65535; p++ {
		if ok(p) {
			return p
		}
	}
	if sysAssign != nil {
		for i := 0; i < 5; i++ {
			if p := sysAssign(); ok(p) {
				return p
			}
		}
	}
	return 0
}

// Result ResolvePair 的结果。
type Result struct {
	Socks, HTTP int
	// SocksMoved / HTTPMoved 表示对应端口与配置值不同（被占用 / 与另一个端口或保留端口重复）。
	SocksMoved, HTTPMoved bool
}

// Changed 是否有任一端口被换掉。
func (r Result) Changed() bool { return r.SocksMoved || r.HTTPMoved }

// OK 两个端口都找到了。
func (r Result) OK() bool { return r.Socks > 0 && r.HTTP > 0 }

// ResolvePair 为 SOCKS 与 HTTP 入站挑端口。reserved 是不能占用的端口（如 TUN 的 UDP 入站），
// forceSocks / forceHTTP 为 true 时即使探测显示可用也要换（真正监听时才发现被占用的情况）。
// 两个端口互不相同。
func ResolvePair(socks, http int, reserved []int, forceSocks, forceHTTP bool, busy Busy, sysAssign func() int) Result {
	avoid := map[int]bool{}
	for _, p := range reserved {
		if p > 0 {
			avoid[p] = true
		}
	}
	sAvoid := copyAvoid(avoid)
	if forceSocks {
		sAvoid[socks] = true
	}
	s := Pick(socks, sAvoid, busy, sysAssign)

	hAvoid := copyAvoid(avoid)
	if s > 0 {
		hAvoid[s] = true
	}
	if forceHTTP {
		hAvoid[http] = true
	}
	h := Pick(http, hAvoid, busy, sysAssign)
	return Result{Socks: s, HTTP: h, SocksMoved: s != socks, HTTPMoved: h != http}
}

func copyAvoid(m map[int]bool) map[int]bool {
	out := make(map[int]bool, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}
