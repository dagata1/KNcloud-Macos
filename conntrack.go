package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

// 换节点后让「存量连接」也立刻换出口。
//
// 热切换 proxy 出站只影响之后新建的连接：已建立的非 mux 连接各自握着到旧节点
// 服务器的底层 TCP，浏览器 / 系统代理客户端的 keep-alive 连接会一直走旧节点，
// 出口 IP 迟迟不变。
//
// 做法：用 internet.UseAlternativeSystemDialer 把 Xray 的系统拨号器换成一个
// 记账的包装（底层仍是 Xray 自带的 DefaultSystemDialer，sockopt 行为不变），
// 记下「主内核实例的 proxy 出站」拨出的每条 TCP 连接及其拨号时的代际号。
// 热切换时先推进代际，新 handler 装好后关掉旧代际的连接：Xray 侧链路随之报错收尾，
// 客户端那头的入站连接也被关闭，客户端重连后自然落到新节点上。
//
// 识别依据：拨号 ctx 里最后一个 session.Outbound 的 Tag（分发器在选中 handler 后写入）
// 加上 ctx 中的 *core.Instance —— 测速用的临时实例同样叫 proxy，但实例不同，不会被误杀。
// 新旧 handler 的 tag 相同，只能靠代际区分（见 commitProxyOutboundLocked 的时序）。
//
// 只包装 TCP：UDP 拨号返回的 *internet.PacketConnWrapper 会被 quic/splithttp 传输层做类型断言，
// 包一层会破坏它们；UDP 会话本身有空闲超时，不做追踪。mux 底层连接的拨号 ctx 不带 tag，
// 由关闭旧 handler（释放其 mux worker）负责切断。

// outboundConnTracker 是全局唯一的记账拨号器。在 init 中注册：此时还没有任何
// Xray 实例在拨号，满足 UseAlternativeSystemDialer「调用方保证无竞争」的要求。
var outboundConnTracker = newConnTracker(&internet.DefaultSystemDialer{}, proxyOutboundTag)

func init() {
	internet.UseAlternativeSystemDialer(outboundConnTracker)
}

type connTracker struct {
	base   internet.SystemDialer
	tag    string // 只追踪此 tag 的出站连接
	instOf func(context.Context) *xcore.Instance
	mu     sync.Mutex
	gen    uint64
	nextID uint64
	conns  map[uint64]*trackedConn
	swept  map[*xcore.Instance]uint64 // 每个实例已清扫到的代际（不含）
}

func newConnTracker(base internet.SystemDialer, tag string) *connTracker {
	return &connTracker{base: base, tag: tag, instOf: xcore.FromContext, conns: make(map[uint64]*trackedConn)}
}

// Dial 实现 internet.SystemDialer。
func (t *connTracker) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	// 代际号取「开始拨号」时的值：切换前就已在拨的旧连接，即使在切换之后才拨通，
	// 也会被识别为旧代际并立即关闭。
	t.mu.Lock()
	gen := t.gen
	t.mu.Unlock()

	conn, err := t.base.Dial(ctx, src, dest, sockopt)
	if err != nil || conn == nil || dest.Network != xnet.Network_TCP {
		return conn, err
	}
	tag := ""
	if obs := session.OutboundsFromContext(ctx); len(obs) > 0 {
		tag = obs[len(obs)-1].Tag
	}
	inst := t.instOf(ctx)
	if tag != t.tag || inst == nil {
		return conn, nil
	}

	tc := &trackedConn{Conn: conn, tracker: t, inst: inst, gen: gen}
	t.mu.Lock()
	if t.isSweptLocked(inst, gen) {
		t.mu.Unlock()
		conn.Close()
		return nil, errors.New("outbound switched while dialing")
	}
	t.nextID++
	tc.id = t.nextID
	t.conns[tc.id] = tc
	t.mu.Unlock()
	return tc, nil
}

// DestIpAddress 实现 internet.SystemDialer。
func (t *connTracker) DestIpAddress() net.IP {
	return t.base.DestIpAddress()
}

// isSweptLocked 判断 inst 上代际 gen 的连接是否已被清扫。实例数量极少
// （只有主内核启动才会产生新实例），且实例关闭时由 Forget 清理。
func (t *connTracker) isSweptLocked(inst *xcore.Instance, gen uint64) bool {
	cut, ok := t.swept[inst]
	return ok && gen < cut
}

// Advance 推进代际并返回新的代际号。之后开始的拨号都属于新代际。
func (t *connTracker) Advance() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gen++
	return t.gen
}

// CloseBefore 关闭 inst 上所有代际号小于 gen 的已追踪连接，并让此后才拨通的
// 旧代际连接一拨通就被关闭。返回关闭的连接数。
func (t *connTracker) CloseBefore(inst *xcore.Instance, gen uint64) int {
	t.mu.Lock()
	if t.swept == nil {
		t.swept = make(map[*xcore.Instance]uint64)
	}
	if gen > t.swept[inst] {
		t.swept[inst] = gen
	}
	var victims []*trackedConn
	for id, c := range t.conns {
		if c.inst == inst && c.gen < gen {
			victims = append(victims, c)
			delete(t.conns, id)
		}
	}
	t.mu.Unlock()
	// 锁外关闭：Close 可能阻塞在内核调用上，也会回调 remove。
	for _, c := range victims {
		c.Conn.Close()
	}
	return len(victims)
}

// Forget 在实例关闭后丢弃它的记账（连接已随实例关闭）。
func (t *connTracker) Forget(inst *xcore.Instance) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.swept, inst)
	for id, c := range t.conns {
		if c.inst == inst {
			delete(t.conns, id)
		}
	}
}

// count 返回 inst 上仍在追踪的连接数（测试用）。
func (t *connTracker) count(inst *xcore.Instance) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, c := range t.conns {
		if c.inst == inst {
			n++
		}
	}
	return n
}

func (t *connTracker) remove(id uint64) {
	t.mu.Lock()
	delete(t.conns, id)
	t.mu.Unlock()
}

// trackedConn 包装出站 TCP 连接，Close 时从记账中移除。
type trackedConn struct {
	net.Conn
	tracker *connTracker
	inst    *xcore.Instance
	gen     uint64
	id      uint64
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.tracker.remove(c.id) })
	return c.Conn.Close()
}

// SyscallConn 透传给底层连接，保留 Xray buf 包的 readv 快速路径。
func (c *trackedConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("underlying connection does not support SyscallConn")
}
