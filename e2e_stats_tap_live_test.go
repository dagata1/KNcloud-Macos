//go:build e2elive && taptest

package main

// 实机：流量统计口径 + 四模式互斥（TAP 后端）。结果逐行 "ROW |"。

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/sys/windows"
)

const mb = 1024 * 1024

func inboundTotals(a *App) (up, down int64) {
	inst := a.statsInst.get()
	if inst == nil {
		return
	}
	mgr := inst.GetFeature(stats.ManagerType()).(stats.Manager)
	for _, tag := range []string{"socks-in", "http-in", tunUDPInboundTag} {
		if c := mgr.GetCounter("inbound>>>" + tag + ">>>traffic>>>uplink"); c != nil {
			up += c.Value()
		}
		if c := mgr.GetCounter("inbound>>>" + tag + ">>>traffic>>>downlink"); c != nil {
			down += c.Value()
		}
	}
	return
}

func curlRange(proxy, url, rng string, maxSec int) string {
	out, _ := exec.Command("curl.exe", "-4", "-s", "-o", "NUL", "-r", rng, "-m", fmt.Sprint(maxSec), "-L", "-x", proxy,
		"-w", "bytes=%{size_download} time=%{time_total} speed=%{speed_download} code=%{http_code}", url).Output()
	return strings.TrimSpace(string(out))
}

// tapAdapterOctets 旧实现 TUN 下用的接口计数（GetIfEntry2Ex，ifIndex 21 = "SSTAP 1"）
func tapAdapterOctets() string {
	row := windows.MibIfRow2{InterfaceIndex: 21}
	if err := windows.GetIfEntry2Ex(0, &row); err != nil {
		return "err:" + err.Error()
	}
	return fmt.Sprintf("out=%.2fMB in=%.2fMB", float64(row.OutOctets)/mb, float64(row.InOctets)/mb)
}

type sampler struct {
	stop    chan struct{}
	wg      sync.WaitGroup
	maxUp   atomic.Int64
	maxDown atomic.Int64
}

func startSampler(a *App) *sampler {
	s := &sampler{stop: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tk.C:
				a.sampleTraffic()
				u, d, _, _ := a.traffic.snapshot()
				if u > s.maxUp.Load() {
					s.maxUp.Store(u)
				}
				if d > s.maxDown.Load() {
					s.maxDown.Store(d)
				}
			}
		}
	}()
	return s
}

func (s *sampler) close() { close(s.stop); s.wg.Wait() }

func measure(t *testing.T, a *App, label string, fn func() string) (du, dd int64) {
	a.sampleTraffic()
	u0, d0 := a.traffic.totals()
	iu0, id0 := inboundTotals(a)
	tap0 := tapAdapterOctets()
	s := startSampler(a)
	res := fn()
	time.Sleep(1500 * time.Millisecond)
	s.close()
	a.sampleTraffic()
	u1, d1 := a.traffic.totals()
	iu1, id1 := inboundTotals(a)
	du, dd = u1-u0, d1-d0
	st := a.GetCoreStatus()
	t.Logf("ROW | %s | curl: %s | NEW proxy-outbound Δup=%.2fMB Δdown=%.2fMB (peak %s up / %s down) | OLD inbound Δup=%.2fMB Δdown=%.2fMB | TAP octets %s → %s | UI 累计 上行 %s 下行 %s",
		label, res, float64(du)/mb, float64(dd)/mb, formatSpeed(s.maxUp.Load()), formatSpeed(s.maxDown.Load()),
		float64(iu1-iu0)/mb, float64(id1-id0)/mb, tap0, tapAdapterOctets(), st.TotalUp, st.TotalDown)
	return
}

func TestTapStatsAndModes(t *testing.T) {
	e := setupTap(t, "bypass-cn")
	const foreign = "https://speed.cloudflare.com/__down?bytes=52428800" // 50 MiB
	const cn = "https://dldir1.qq.com/weixin/Windows/WeChatSetup.exe"
	jpIP := nodeExitIP["日本"]

	// A) 系统代理模式（绕过大陆），经 HTTP 入站
	_, dd := measure(t, e.a, "A1 sysproxy bypass-cn: 50MiB cloudflare via proxy", func() string {
		return curlSpeed("http://127.0.0.1:21081", foreign, 90)
	})
	if dd < 48*mb || dd > 60*mb {
		t.Errorf("A1: proxied 50MiB download counted %.2fMB down", float64(dd)/mb)
	}
	du, dd := measure(t, e.a, "A2 sysproxy bypass-cn: 30MiB dldir1.qq.com (CN, direct)", func() string {
		return curlRange("http://127.0.0.1:21081", cn, "0-31457279", 60)
	})
	_ = du
	if dd > 2*mb {
		t.Errorf("A2: direct CN download counted %.2fMB down", float64(dd)/mb)
	}

	// B) TUN（保存的策略是绕过大陆，TUN 必须仍按全局）
	e.start(t, "B TUN")
	st := e.a.GetCoreStatus()
	e.a.mu.RLock()
	bypass := e.a.tunRt.count("bypass")
	e.a.mu.RUnlock()
	t.Logf("ROW | B status | tunnelMode=%v routingMode=%s systemProxy=%v bypassRoutes=%d", st.TunnelMode, st.RoutingMode, st.SystemProxy, bypass)
	if !st.TunnelMode || st.RoutingMode != "bypass-cn" || bypass > len(privateBypassCIDRs) { // 只有私网直连路由，没有 CN 网段
		t.Errorf("TUN must be global without rewriting saved policy: %+v bypass=%d", st, bypass)
	}
	e.check(t, "B TUN global (saved bypass-cn)", jpIP, jpIP)
	_, dd = measure(t, e.a, "B1 TUN: 50MiB cloudflare", func() string { return curlSpeed("", foreign, 90) })
	if dd < 48*mb || dd > 60*mb {
		t.Errorf("B1: TUN 50MiB download counted %.2fMB down", float64(dd)/mb)
	}

	// C) TUN 下点「全局代理」：关 TUN、按全局回到系统代理；期间状态轮询不阻塞
	var maxLat atomic.Int64
	var busySeen atomic.Bool
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			t0 := time.Now()
			s := e.a.GetCoreStatus()
			if d := time.Since(t0).Microseconds(); d > maxLat.Load() {
				maxLat.Store(d)
			}
			if s.Busy {
				busySeen.Store(true)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	t0 := time.Now()
	ok, err := e.a.SetRoutingMode("global")
	dur := time.Since(t0)
	close(stop)
	wg.Wait()
	st = e.a.GetCoreStatus()
	t.Logf("ROW | C TUN → 全局代理 | %v ok=%v err=%v | tunnelMode=%v routingMode=%s | GetCoreStatus max latency during op=%dµs busySeen=%v", dur.Round(time.Millisecond), ok, err, st.TunnelMode, st.RoutingMode, maxLat.Load(), busySeen.Load())
	if !ok || err != nil || st.TunnelMode || st.RoutingMode != "global" {
		t.Errorf("C: want TUN off + global, got %+v err=%v", st, err)
	}
	if maxLat.Load() > 100000 {
		t.Errorf("C: status polling blocked %dµs", maxLat.Load())
	}
	f := extractIP(fetchIP(proxyClient(21081, false)))
	t.Logf("ROW | C sysproxy global exit via http-in | %s (want %s)", f, jpIP)

	// D) 再开 TUN（保存的是 global），点「全局直连」→ 关 TUN + 直连
	e.start(t, "D TUN")
	ok, err = e.a.SetRoutingMode("direct")
	st = e.a.GetCoreStatus()
	t.Logf("ROW | D TUN → 全局直连 | ok=%v err=%v tunnelMode=%v routingMode=%s | routes=%d (baseline %d)", ok, err, st.TunnelMode, st.RoutingMode, routeCount4(), e.baseRoutes)
	if st.TunnelMode || st.RoutingMode != "direct" {
		t.Errorf("D: %+v", st)
	}
	_, dd = measure(t, e.a, "D1 sysproxy direct: 20MiB cloudflare via http-in (direct outbound)", func() string {
		return curlSpeed("http://127.0.0.1:21081", foreign[:strings.Index(foreign, "=")+1]+fmt.Sprint(20*mb), 60)
	})
	if dd > 2*mb {
		t.Errorf("D1: direct-mode download counted %.2fMB", float64(dd)/mb)
	}
	e.a.mu.Lock()
	e.a.routingMode = "bypass-cn"
	e.a.mu.Unlock()
}

// TestStatsDirectCN 系统代理 + 绕过大陆：国内下载走 direct 出站，不计入；对照经代理下载计入。
func TestStatsDirectCN(t *testing.T) {
	a, _ := setupLiveApp(t)
	jp, _ := pickNodes(t, a)
	a.mu.Lock()
	a.routingMode = "bypass-cn"
	a.mu.Unlock()
	if _, err := a.SelectNode(jp.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.ToggleCore(true); !ok || err != nil {
		t.Fatalf("core: %v", err)
	}
	defer a.ToggleCore(false)
	time.Sleep(800 * time.Millisecond)
	_, dd := measure(t, a, "E1 sysproxy bypass-cn: 30MiB dldir1.qq.com (CN, direct)", func() string {
		return curlRange("http://127.0.0.1:21081", "https://dldir1.qq.com/weixin/Windows/WeChatSetup.exe", "0-31457279", 60)
	})
	if dd > 2*mb {
		t.Errorf("E1: direct CN download counted %.2fMB", float64(dd)/mb)
	}
	_, dd = measure(t, a, "E2 sysproxy bypass-cn: 20MiB cloudflare (proxied)", func() string {
		return curlRange("http://127.0.0.1:21081", "https://speed.cloudflare.com/__down?bytes=20971520", "0-20971519", 60)
	})
	if dd < 19*mb || dd > 24*mb {
		t.Errorf("E2: proxied 20MiB counted %.2fMB", float64(dd)/mb)
	}
}
