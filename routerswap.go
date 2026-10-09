package main

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// 运行中切换分流策略（绕过大陆 / 全局 / 直连）而不重启内核。
//
// 整体重启内核切不断存量连接：Xray 关闭实例时只关监听，已接入的 HTTP CONNECT 隧道
// 与 SOCKS 连接仍挂在旧实例上，按旧策略出站；浏览器的明文 HTTP keep-alive 连接
// 也继续由旧实例的分发器按旧规则路由。实测切换后 keep-alive 客户端的出口 IP 一直不变。
//
// 做法：主内核不用 Xray 自带的 router 特性，而用 swappableRouter —— 它把一个普通的
// *router.Router 放在 atomic.Pointer 里，PickRoute 每次读取当前指针。切换策略时新建一个
// router.Router 并整体替换，没有「规则表半新半旧」的中间态，也没有数据竞争
// （Xray 自带的 ReloadRules 是边清空边追加，且 PickRoute 读规则表不加锁）。
// 换完规则后入站监听与同一实例保持不动：新连接（含明文 keep-alive 的后续请求）按新规则路由，
// 已建立的隧道保持原出口不切断（与 v2rayN 一致，进行中的下载不会被打断）。
//
// 接入方式：Xray 按配置消息的类型查找构造函数，router.Config 的构造函数已被 Xray 注册，
// 不能覆盖。所以 startCoreLocked 把配置里的 router.Config 序列化后装进一个
// wrapperspb.BytesValue 消息（Xray 不使用该类型），由这里注册的构造函数还原成 swappableRouter。

// swappableRouterConfigType 是装载 router.Config 的外壳消息类型名。
var swappableRouterConfigType = serial.GetMessageType(&wrapperspb.BytesValue{})

func init() {
	common.Must(common.RegisterConfig((*wrapperspb.BytesValue)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		rc := new(router.Config)
		if err := proto.Unmarshal(cfg.(*wrapperspb.BytesValue).GetValue(), rc); err != nil {
			return nil, err
		}
		s := &swappableRouter{ctx: ctx}
		// 与 Xray 自带 router 的构造方式一致：依赖的特性就绪后再初始化。
		if err := xcore.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, disp routing.Dispatcher) error {
			s.dns, s.ohm, s.disp = d, ohm, disp
			return s.Reload(rc)
		}); err != nil {
			return nil, err
		}
		return s, nil
	}))
}

type swappableRouter struct {
	ctx  context.Context
	dns  dns.Client
	ohm  outbound.Manager
	disp routing.Dispatcher
	cur  atomic.Pointer[router.Router]
}

// Reload 用 cfg 构建一个全新的 router.Router 并原子替换。构建失败时保持原规则。
func (s *swappableRouter) Reload(cfg *router.Config) error {
	if s.ohm == nil {
		return errors.New("router is not initialized yet")
	}
	r := new(router.Router)
	if err := r.Init(s.ctx, cfg, s.dns, s.ohm, s.disp); err != nil {
		return err
	}
	s.cur.Store(r)
	return nil
}

// Type 实现 common.HasType：以 routing.Router 的身份注册，分发器取到的就是它。
func (*swappableRouter) Type() interface{} { return routing.RouterType() }
func (*swappableRouter) Start() error      { return nil }
func (*swappableRouter) Close() error      { return nil }

// PickRoute 实现 routing.Router。
func (s *swappableRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r := s.cur.Load()
	if r == nil {
		return nil, common.ErrNoClue
	}
	return r.PickRoute(ctx)
}

// AddRule / RemoveRule 实现 routing.Router（本程序不用 Xray 的路由 API，仅转发）。
func (s *swappableRouter) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	if r := s.cur.Load(); r != nil {
		return r.AddRule(config, shouldAppend)
	}
	return errors.New("router is not initialized yet")
}

func (s *swappableRouter) RemoveRule(tag string) error {
	if r := s.cur.Load(); r != nil {
		return r.RemoveRule(tag)
	}
	return errors.New("router is not initialized yet")
}

var routerConfigType = serial.GetMessageType(&router.Config{})

// routerConfigOf 取出已构建内核配置里的 router.Config；没有时返回 nil。
func routerConfigOf(cfg *xcore.Config) (*router.Config, error) {
	for _, app := range cfg.App {
		if app.Type != routerConfigType {
			continue
		}
		inst, err := app.GetInstance()
		if err != nil {
			return nil, err
		}
		rc, ok := inst.(*router.Config)
		if !ok {
			return nil, errors.New("unexpected routing config type")
		}
		return rc, nil
	}
	return nil, nil
}

// useSwappableRouter 把配置里的 router.Config 换成可热替换的外壳（就地修改 cfg）。
func useSwappableRouter(cfg *xcore.Config) error {
	for i, app := range cfg.App {
		if app.Type != routerConfigType {
			continue
		}
		inst, err := app.GetInstance()
		if err != nil {
			return err
		}
		raw, err := proto.Marshal(inst)
		if err != nil {
			return err
		}
		cfg.App[i] = serial.ToTypedMessage(&wrapperspb.BytesValue{Value: raw})
		return nil
	}
	return nil
}

// swappableRouterOf 返回实例上的可热替换 router；实例不是用它启动的则返回 nil。
func swappableRouterOf(inst *xcore.Instance) *swappableRouter {
	if inst == nil {
		return nil
	}
	sr, _ := inst.GetFeature(routing.RouterType()).(*swappableRouter)
	return sr
}
