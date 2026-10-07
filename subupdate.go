package main

import (
	"fmt"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// subUpdateWeekly 自动更新订阅固定每周一次（频繁请求官网/订阅地址容易导致域名被墙）。
const subUpdateWeekly = 7 * 24 * time.Hour

// subUpdateInterval 返回自动更新订阅的间隔；-1 表示关闭（返回 0），其余一律每周。
// 旧版本保存的 1/3/6/12/24 小时也按每周处理。
func subUpdateInterval(hours int) time.Duration {
	if hours < 0 {
		return 0
	}
	return subUpdateWeekly
}

// subAutoUpdateDue 判断是否到了自动更新时间（纯函数，便于测试）。
func subAutoUpdateDue(now time.Time, last int64, interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	if last <= 0 {
		return false // 启动时已有一次同步，失败时等启动流程处理，避免与之并发
	}
	return now.Sub(time.Unix(last, 0)) >= interval
}

// subAutoUpdateLoop 每分钟检查一次；登录了官网账户且距上次成功更新满一周时，
// 查询最新官网地址（每周一次）、刷新套餐/流量并同步订阅节点，完成后通知界面刷新。
// 上次更新时间持久化在配置里，重启不影响计时；从未更新过（last 为 0）时 30 分钟后补一次。
func (a *App) subAutoUpdateLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	started := time.Now()
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-ticker.C:
			a.mu.RLock()
			loggedIn := a.account.LoggedIn && a.account.SubID != ""
			interval := subUpdateInterval(a.settings.SubUpdateHours)
			a.mu.RUnlock()
			if !loggedIn || interval <= 0 {
				continue
			}
			last := a.subLastAuto.Load()
			due := subAutoUpdateDue(now, last, interval)
			if last <= 0 && now.Sub(started) >= 30*time.Minute {
				due = true // 启动同步没成功：补一次
				started = now
			}
			if !due || a.traySubUpdating.Load() {
				continue
			}
			a.runAutoSubUpdate()
		}
	}
}

func (a *App) runAutoSubUpdate() {
	if !a.traySubUpdating.CompareAndSwap(false, true) {
		return
	}
	tray.requestRebuild()
	defer func() {
		a.traySubUpdating.Store(false)
		tray.requestRebuild()
	}()
	a.weeklyResolveDomain(time.Now()) // 每周最多查询一次最新官网地址
	_, err := a.RefreshAccount()
	if err == nil {
		err = a.SyncNodes()
	}
	if err != nil {
		// 失败也记一次时间，避免每分钟重试刷屏；下个间隔再试
		a.subLastAuto.Store(time.Now().Unix())
		a.addLogInternal("warn", fmt.Sprintf("Auto subscription update failed: %v", err))
		return
	}
	a.addLogInternal("info", "Auto subscription update done")
	if ctx := a.appCtx(); ctx != nil {
		runtime.EventsEmit(ctx, "kncloud:refresh")
	}
}
