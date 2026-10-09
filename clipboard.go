package main

import "fmt"

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
	nodes, skipped := ParseShareLinksReport(text)
	if msg := skippedLinksLog(skipped); msg != "" {
		a.addLogInternal("warn", msg)
	}
	if len(nodes) == 0 {
		return 0, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range nodes {
		nodes[i].ID = newNodeID()
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
