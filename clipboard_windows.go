package main

// 节点列表的 Ctrl+C / Ctrl+V 支持：分享链接复制到剪贴板 / 从剪贴板导入。
// 直接走 Win32 剪贴板 API（CF_UNICODETEXT），不经过 PowerShell —— 没有控制台
// 代码页编码问题（中文节点名），也没有每次拉起进程的几百毫秒延迟。

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procGetClipboardData = user32.NewProc("GetClipboardData")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// openClipboard 打开剪贴板。系统同一时刻只允许一个打开者（其它程序可能正占着），
// 短暂重试几次再放弃。
func openClipboard() error {
	for i := 0; i < 6; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("clipboard is busy")
}

// setClipboardText 以 CF_UNICODETEXT 写入剪贴板。
// 成功后内存块所有权归系统（SetClipboardData 语义），不要 GlobalFree。
func setClipboardText(text string) error {
	if err := openClipboard(); err != nil {
		return err
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	u16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	size := len(u16) * 2
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if h == 0 {
		return fmt.Errorf("GlobalAlloc failed")
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), size), unsafe.Slice((*byte)(unsafe.Pointer(&u16[0])), size))
	if r, _, _ := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		return fmt.Errorf("SetClipboardData failed")
	}
	return nil
}

// clipboardText 读取剪贴板文本；剪贴板为空或没有文本时返回空串。
func clipboardText() (string, error) {
	if err := openClipboard(); err != nil {
		return "", err
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)
	u := unsafe.Slice((*uint16)(unsafe.Pointer(p)), 1<<20)
	n := 0
	for n < len(u) && u[n] != 0 {
		n++
	}
	return windows.UTF16ToString(u[:n]), nil
}

// CopyNodeShareLink 生成选中节点的分享链接并写入系统剪贴板
func (a *App) CopyNodeShareLink(id string) (bool, error) {
	a.mu.RLock()
	var node NodeItem
	found := false
	for i := range a.nodes {
		if a.nodes[i].ID == id {
			node = a.nodes[i]
			found = true
			break
		}
	}
	a.mu.RUnlock()
	if !found {
		return false, fmt.Errorf("node not found")
	}
	link, err := BuildShareLink(node)
	if err != nil {
		return false, err
	}
	if err := setClipboardText(link); err != nil {
		return false, err
	}
	a.addLogInternal("info", fmt.Sprintf("Node share link copied to clipboard: [%s] %s", node.Protocol, node.Name))
	return true, nil
}

// ImportNodesFromClipboard 读取剪贴板并导入其中可识别的节点分享链接，返回导入数量。
// 剪贴板内容不是分享链接时返回 0（前端静默处理，不打扰用户）。
func (a *App) ImportNodesFromClipboard() (int, error) {
	text, err := clipboardText()
	if err != nil {
		return 0, err
	}
	nodes := ParseShareLinks(text)
	if len(nodes) == 0 {
		return 0, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range nodes {
		nodes[i].ID = fmt.Sprintf("node-%d", time.Now().UnixNano()+int64(i))
		if nodes[i].Group == "" {
			nodes[i].Group = "Custom"
		}
		a.nodes = append(a.nodes, nodes[i])
	}
	a.addLogInternal("info", fmt.Sprintf("Imported %d node(s) from clipboard", len(nodes)))
	a.savePersisted()
	tray.requestRebuild()
	return len(nodes), nil
}
