package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

// lastNodeID 最近一次生成的节点 ID 数值。Windows 上 time.Now() 的精度只有约 0.5~15.6ms，
// 旧写法 UnixNano()+i 在同一时钟刻度内连续两批导入会生成完全相同的 ID。
var lastNodeID atomic.Int64

// newNodeID 生成进程内严格递增、格式仍为 node-<数字> 的节点 ID。
func newNodeID() string {
	for {
		last := lastNodeID.Load()
		now := time.Now().UnixNano()
		if now <= last {
			now = last + 1
		}
		if lastNodeID.CompareAndSwap(last, now) {
			return fmt.Sprintf("node-%d", now)
		}
	}
}

// dedupeNodeIDsLocked 给空 ID 或与前面节点重复的 ID 重新分配唯一 ID，返回修正的个数
// （调用方需持有写锁，或在 App 尚未共享时调用）。
//
// 重复 ID 时，按 ID 查找节点永远命中第一个：点列表里其它同 ID 的节点会被当成
// 「当前已连接」的那个，切换无法进行。被改 ID 的重复节点一律取消 Active，
// activeNodeID 仍指向保留原 ID 的第一个节点。
func (a *App) dedupeNodeIDsLocked() int {
	seen := make(map[string]bool, len(a.nodes))
	fixed := 0
	for i := range a.nodes {
		id := a.nodes[i].ID
		if id != "" && !seen[id] {
			seen[id] = true
			continue
		}
		nid := newNodeID()
		for seen[nid] {
			nid = newNodeID()
		}
		a.nodes[i].ID = nid
		a.nodes[i].Active = false
		seen[nid] = true
		fixed++
	}
	if fixed > 0 && a.activeNodeID != "" {
		for i := range a.nodes {
			a.nodes[i].Active = a.nodes[i].ID == a.activeNodeID
		}
	}
	return fixed
}
