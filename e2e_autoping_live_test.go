//go:build e2elive && taptest

package main

// 实机：后台自动测速填充延迟 + TUN 下测速出站是否绑物理网卡（TAP 后端）。结果逐行 "ROW |"。
// 本文件不提交（含本机环境假设）。

import (
	"net"
	"strconv"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAutoPingLive 系统代理/内核关闭状态下跑一轮 autoPingRound（与启动、订阅更新后的后台测速同一函数）。
func TestAutoPingLive(t *testing.T) {
	a, _ := setupLiveApp(t)
	a.mu.Lock()
	for i := range a.nodes {
		a.nodes[i].Delay = -1
	}
	n := len(a.nodes)
	a.mu.Unlock()
	t0 := time.Now()
	a.autoPingRound()
	el := time.Since(t0)
	ok, to, un := 0, 0, 0
	for _, nd := range a.GetNodes() {
		switch {
		case nd.Delay > 0:
			ok++
		case nd.Delay == -2:
			to++
		default:
			un++
		}
		t.Logf("ROW | node | %s | %s | delay=%d", nd.Name, nd.Protocol, nd.Delay)
	}
	t.Logf("ROW | auto ping round | nodes=%d ok=%d timeout=%d untested=%d | %v (concurrency %d)", n, ok, to, un, el.Round(time.Millisecond), pingConcurrency)
	if ok == 0 || un != 0 {
		t.Errorf("auto ping did not populate delays")
	}
	dumpLogs(t, a)
}

// netstat 轮询：记录到 ips 中任一地址的 TCP 连接的本地地址
type connWatch struct {
	stop  chan struct{}
	wg    sync.WaitGroup
	mu    sync.Mutex
	local map[string]int
}

func watchConns(ips []string) *connWatch {
	w := &connWatch{stop: make(chan struct{}), local: map[string]int{}}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for {
			select {
			case <-w.stop:
				return
			default:
			}
			out, _ := exec.Command("netstat", "-ano", "-p", "TCP").Output()
			for _, ln := range strings.Split(string(out), "\n") {
				f := strings.Fields(ln)
				if len(f) < 3 {
					continue
				}
				for _, ip := range ips {
					if f[2] == ip {
						la := f[1]
						if i := strings.LastIndex(la, ":"); i > 0 {
							la = la[:i]
						}
						if len(f) >= 4 {
							la += " " + f[3]
						}
						w.mu.Lock()
						w.local[la]++
						w.mu.Unlock()
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return w
}

func (w *connWatch) done() map[string]int {
	close(w.stop)
	w.wg.Wait()
	return w.local
}

// TestAutoPingTunBinding TUN（TAP 后端，global）运行中：
//   - 旧行为（不绑网卡）测新加坡节点：到节点的连接从 TAP 网卡地址发出（经当前节点绕行）；
//   - 新行为（pingNode，TUN 下绑物理网卡）：到节点的连接从物理网卡地址发出；
//   - 一整轮自动测速后 TUN 出口仍是当前节点（现网连接不受影响）。
func TestAutoPingTunBinding(t *testing.T) {
	e := setupTap(t, "global")
	var sgIPs []string
	if ip := net.ParseIP(e.sg.Address); ip != nil {
		sgIPs = []string{ip.String()}
	} else {
		addrs, _ := net.LookupHost(e.sg.Address)
		for _, s := range addrs {
			if net.ParseIP(s).To4() != nil {
				sgIPs = append(sgIPs, s)
			}
		}
	}
	t.Logf("ROW | sg node %s -> %v", e.sg.Address, sgIPs)
	var sgEPs []string
	for _, ip := range sgIPs {
		sgEPs = append(sgEPs, net.JoinHostPort(ip, strconv.Itoa(e.sg.Port)))
	}

	e.start(t, "global")
	before := curl4("https://ifconfig.me/ip")
	e.a.mu.RLock()
	egress := e.a.tunEgressIface
	e.a.mu.RUnlock()
	t.Logf("ROW | TUN on | egress iface=%q | exit ip=%s", egress, before)

	// 本机全部节点共用同一中转 IP，当前节点的 /32 绕过路由会让「不绑网卡」也直连，看不出差别。
	// （摘掉这条 /32 会让主内核不受 sockopt 约束的 SS UDP 回环进 TUN，不可取。）
	// 所以另用一个不在任何 /32 里的探针「节点」1.0.0.1:80：TCP 能建上（SS 握手必然失败），
	// 只看到它的 TCP 连接从哪块网卡发出。
	e.a.mu.RLock()
	for _, r := range e.a.tunRt.entries("host") {
		t.Logf("ROW | host route %s", r)
	}
	e.a.mu.RUnlock()
	probe := e.sg
	probe.Address, probe.Port = "1.0.0.1", 80
	probeEP := []string{"1.0.0.1:80"}

	w := watchConns(probeEP)
	old := testNodeRealDelay(probe, "")
	time.Sleep(300 * time.Millisecond)
	oldLocal := w.done()
	t.Logf("ROW | probe unbound (old behaviour) | delay=%d | local addrs: %v", old, oldLocal)

	// 换端口：上一步留下的 TIME_WAIT 连接不能混进这一步的观测
	probe.Port = 443
	w = watchConns([]string{"1.0.0.1:443"})
	nb := testNodeRealDelay(probe, egress)
	time.Sleep(300 * time.Millisecond)
	newLocal := w.done()
	t.Logf("ROW | probe bound to %q (new) | delay=%d | local addrs: %v", egress, nb, newLocal)
	if len(newLocal) == 0 {
		t.Errorf("probe connection not observed")
	}
	for la := range newLocal {
		if strings.HasPrefix(la, "10.198.") || strings.HasPrefix(la, "172.19.") {
			t.Errorf("bound probe went through the TAP adapter (local %s)", la)
		}
	}

	w = watchConns(sgEPs)
	nw := e.a.pingNode(e.sg.ID, true)
	time.Sleep(300 * time.Millisecond)
	t.Logf("ROW | real sg node pingNode under TUN | delay=%d | local addrs: %v", nw, w.done())
	if nw <= 0 {
		t.Errorf("bound test failed: %d", nw)
	}

	t0 := time.Now()
	e.a.autoPingRound()
	ok := 0
	for _, nd := range e.a.GetNodes() {
		if nd.Delay > 0 {
			ok++
		}
	}
	after := curl4("https://ifconfig.me/ip")
	t.Logf("ROW | auto ping round under TUN | ok=%d/%d | %v | exit ip before=%s after=%s", ok, len(e.a.GetNodes()), time.Since(t0).Round(time.Millisecond), before, after)
	if after != before {
		t.Errorf("exit IP changed during auto ping: %s -> %s", before, after)
	}
}
