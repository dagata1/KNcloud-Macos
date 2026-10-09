package main

import (
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

//go:embed geo/cn-routes.txt
var cnRoutesTxt string

const (
	tunLogTag = "TUN"

	// SSTap 方案核心参数（复刻 SSTap-beta 的 TAP 分流机制）
	tunIfaceName = "KNcloud-TAP"       // 固定虚拟网卡名（对应 SSTAP 1）
	tunGateway   = "172.19.0.1"        // 虚拟网卡网关地址（/30）
	tunDnsAddr   = "198.18.0.2"        // 写入虚拟网卡的系统 DNS，UDP:53 由转发器的 DNS 中继应答
	tunMetric    = 1                   // 虚拟网卡接口 metric（对应 SSTap 抢占 DNS 优先级）
	tunGateway6  = "fdfe:dcba:9876::1" // 虚拟网卡 IPv6 地址（/126），配合 2000::/3 分流路由堵 IPv6 泄漏
)

// runHidden 执行一个控制台程序并取回输出，全程不闪黑窗。
// runHiddenTimeout 外部命令（netsh / ipconfig / powershell）的默认上限。
// 这些命令大多在持有 a.mu 时调用：没有上限的话，一个卡住的子进程会让整个程序
// （界面绑定、换节点、退出）跟着无限期挂起。
const runHiddenTimeout = 45 * time.Second

func runHidden(name string, args ...string) ([]byte, error) {
	return runHiddenWithin(runHiddenTimeout, name, args...)
}

// runHiddenWithin 无窗口运行外部命令，超过 d 强制结束子进程并返回错误。
func runHiddenWithin(d time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = hiddenProc()
	cmd.WaitDelay = 2 * time.Second // 孙进程占着输出管道时也不无限等待
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, d)
	}
	return out, err
}

// ------------------------- 路由引擎（复刻 SSTap 的静态分流路由） -------------------------
//
// 查询走旧版 IP Helper API（GetBestRoute / GetIpForwardTable）：MIB_IPFORWARDROW 是纯
// 14-DWORD 结构，无对齐歧义。写入/删除走 v2 API（tunroutes.go，手工排布 MIB_IPFORWARD_ROW2）。
// IP 地址以网络序存储于 DWORD：字段值 == binary.BigEndian.Uint32(ip)。

// lookupNodeIPv4s 解析节点服务器的 IPv4 地址（最多 4 个）；Address 为 IP 字面量时直接返回
// isBogusUnicastV4 判断该 IPv4 是否不可能作为节点服务器地址（组播/保留/链路本地等）。
// 系统 DNS 对被墙域名的污染应答经常落在这类地址段，TUN 启动前必须剔除。
func isBogusUnicastV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return true
	}
	if v4.IsUnspecified() || v4.IsLoopback() || v4.IsMulticast() ||
		v4.IsLinkLocalUnicast() || v4.IsLinkLocalMulticast() {
		return true
	}
	// 240.0.0.0/4 保留段（含 255.255.255.255，IsMulticast 不覆盖）
	if v4[0] >= 240 {
		return true
	}
	// 198.18.0.0/15 基准测试段（各类 fake-ip 方案的惯用段）
	if v4[0] == 198 && v4[1] == 18 {
		return true
	}
	return false
}

func filterValidIPv4s(ips []net.IP) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil || isBogusUnicastV4(v4) {
			continue
		}
		out = append(out, v4)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

// lookupIPv4Via 绕过系统 DNS，直接向指定公共 DNS 查询 A 记录并过滤非法地址。
// 用于系统 DNS 被污染（应答全部落在非法段）时的兜底。
func lookupIPv4Via(host, dns string) []net.IP {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", net.JoinHostPort(dns, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	raw := make([]net.IP, 0, len(ips))
	for _, a := range ips {
		raw = append(raw, a.IP)
	}
	return filterValidIPv4s(raw)
}

// lookupNodeIPv4s 解析节点服务器的 IPv4。系统 DNS 对被墙域名可能返回污染应答
// （组播/保留段等非法地址），先解析再剔除；全部非法时改用公共 DNS
// （223.5.5.5 / 119.29.29.29）直查兜底。
func lookupNodeIPv4s(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil && !isBogusUnicastV4(v4) {
			return []net.IP{v4}
		}
		return nil
	}
	for _, dns := range []string{"223.5.5.5", "119.29.29.29"} {
		if ips := lookupIPv4Via(host, dns); len(ips) > 0 {
			return ips
		}
	}
	return filterValidIPv4s(mustLookupIPs(host))
}

func mustLookupIPs(host string) []net.IP {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

// nodeIPCache 缓存节点域名 -> IPv4 解析结果。
// 开启/切换 TUN 都要解析节点地址（写防回环 /32 用），而 DNS 查询要 1~2 秒；
// 开关 TUN 是用户手动操作，缓存几分钟能明显降低体感延迟。
var nodeIPCache = struct {
	sync.Mutex
	m map[string]nodeIPCacheEntry
}{m: map[string]nodeIPCacheEntry{}}

type nodeIPCacheEntry struct {
	ips   []net.IP
	until time.Time
}

const nodeIPCacheTTL = 5 * time.Minute

// nodeLookupBudget 解析节点地址最多等待的时间。调用方（TUN 开启 / 换节点）持有 a.mu，
// 系统解析器 net.LookupIP 本身没有超时，被墙或断网时可能卡很久。
const nodeLookupBudget = 8 * time.Second

// lookupNodeIPv4sCached 带缓存、有时间上限的解析；解析失败不写缓存，避免缓存住空结果。
// 超时返回 nil；后台解析完成后照常写缓存，下次调用直接命中。
func lookupNodeIPv4sCached(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return lookupNodeIPv4s(host) // IP 字面量无需解析
	}
	res := make(chan []net.IP, 1)
	go func() { res <- lookupNodeIPv4sCachedBlocking(host) }()
	select {
	case ips := <-res:
		return ips
	case <-time.After(nodeLookupBudget):
		vlog("resolve node %s: timed out after %s", host, nodeLookupBudget)
		return nil
	}
}

func lookupNodeIPv4sCachedBlocking(host string) []net.IP {
	key := strings.ToLower(host)
	now := time.Now()
	nodeIPCache.Lock()
	if e, ok := nodeIPCache.m[key]; ok && now.Before(e.until) && len(e.ips) > 0 {
		ips := e.ips
		nodeIPCache.Unlock()
		return ips
	}
	nodeIPCache.Unlock()

	ips := lookupNodeIPv4s(host)
	if len(ips) == 0 {
		return nil
	}
	nodeIPCache.Lock()
	nodeIPCache.m[key] = nodeIPCacheEntry{ips: ips, until: now.Add(nodeIPCacheTTL)}
	nodeIPCache.Unlock()
	return ips
}

// rangeToCIDRs 将闭区间 [start, end] 拆成 CIDR 列表
func rangeToCIDRs(start, end uint64) []net.IPNet {
	var out []net.IPNet
	for start <= end {
		align := uint64(1) << 32
		if start != 0 {
			align = start & (^start + 1) // 最低置位比特 = 最大对齐块
		}
		rem := end - start + 1
		size := align
		if rem < size {
			size = 1
			for size*2 <= rem {
				size *= 2
			}
		}
		prefixLen := 32 - (bits.Len64(size) - 1)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(start))
		mask := net.CIDRMask(prefixLen, 32)
		out = append(out, net.IPNet{IP: ip.Mask(mask), Mask: mask})
		start += size
	}
	return out
}

// tunVerbose 自检（--tun-selftest）时输出的逐步日志；正常运行保持安静
var tunVerbose bool

func vlog(format string, args ...interface{}) {
	if tunVerbose {
		fmt.Printf("[tun] "+format+"\n", args...)
	}
}

// ifaceHasAddr 判断网卡上是否已配置指定 IP（用于 IPv6 路由前置检查）
func ifaceHasAddr(ifIdx uint32, ip string) bool {
	iface, err := net.InterfaceByIndex(int(ifIdx))
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
			return true
		}
	}
	return false
}
