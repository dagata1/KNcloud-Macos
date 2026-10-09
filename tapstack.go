package main

// tapstack.go —— SSTap 核心方案的 Go 重写（wintun 网卡 + 链路端点 + SOCKS5 客户端）。
//
// SSTap 快的原因：TAP-Windows 虚拟网卡（固定 GUID）驱动装一次就永久常驻，
// 开关全局代理只是增删路由表条目，从不创建/销毁网卡。
//
// 本文件用 Go 原地重写 SSTap 的三层核心：
//  1. 常驻虚拟网卡：直接调用 wintun.dll（已内嵌）以固定 GUID 创建适配器，
//     首次创建后永久复用（断电重启仍在），绝不删除；
//  2. 用户态 TCP/IP 协议栈：gvisor netstack 直接消费网卡收发包
//     （对应 SSTap 的 ss-tap/tun2socks）；
//  3. 转发出口：TCP 走 SOCKS5 CONNECT、UDP 走 SOCKS5 UDP ASSOCIATE，
//     DNS（UDP:53）经物理网卡直连公共 DNS（223.5.5.5）防污染防回环。
//
// 出口指向本机 Xray 内核的 SOCKS 入站（v2rayN 方案），两套方案就此合并：
// Xray 常驻做代理大脑，TUN 只负责「抓流量」，开关全部是秒级路由操作。

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// tapMTU 虚拟网卡与 gVisor 链路的 MTU。TCP 在本机协议栈里终结、不会原样走到
// 物理网络，所以可以用巨型帧：单包 9000 字节让每包固定开销（两次 DLL 调用、一次
// 拷贝、一次协议栈分发）摊薄约 6 倍。
const tapMTU = 9000

// ------------------------- wintun.dll API -------------------------

// ------------------------- 常驻适配器管理 -------------------------

// ------------------------- gvisor 链路端点 -------------------------

// deliverIPPacket 按 IP 版本把一个完整 IP 包交给协议栈（data 的所有权移交给协议栈）。
func deliverIPPacket(disp stack.NetworkDispatcher, data []byte) {
	if len(data) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch data[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	disp.DeliverNetworkPacket(proto, pkt)
	pkt.DecRef()
}

// ------------------------- SOCKS5 客户端 -------------------------

// socksDialTCP 经 Xray 的 SOCKS5 入站建立到 dst 的 TCP 隧道（CONNECT）
func socksDialTCP(socksAddr string, dst *net.TCPAddr, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	// greeting: 无认证
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	rsp := make([]byte, 2)
	if _, err := io.ReadFull(conn, rsp); err != nil || rsp[0] != 0x05 || rsp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting failed")
	}
	// CONNECT：ATYP + 地址 + 端口
	var req []byte
	if ip4 := dst.IP.To4(); ip4 != nil {
		req = append(req, 0x05, 0x01, 0x00, 0x01)
		req = append(req, ip4...)
	} else {
		req = append(req, 0x05, 0x01, 0x00, 0x04)
		req = append(req, dst.IP.To16()...)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(dst.Port))
	req = append(req, port...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 CONNECT rejected (code=%d)", replyCode(head))
	}
	// 跳过 BIND 地址 + 端口
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x03:
		skip = 1
	case 0x04:
		skip = 16
	}
	skipBuf := make([]byte, skip+2)
	if _, err := io.ReadFull(conn, skipBuf); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func replyCode(head []byte) int {
	if len(head) > 1 {
		return int(head[1])
	}
	return -1
}

// socksUDPChannel 经 Xray SOCKS5 UDP ASSOCIATE 建立的双向 UDP 通道
type socksUDPChannel struct {
	control net.Conn     // 关联控制连接
	udp     *net.UDPConn // 关联返回的转发 socket
}

func socksDialUDP(socksAddr string, timeout time.Duration) (*socksUDPChannel, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	rsp := make([]byte, 2)
	if _, err := io.ReadFull(conn, rsp); err != nil || rsp[0] != 0x05 || rsp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting failed")
	}
	// UDP ASSOCIATE：绑定地址填 0（由服务端返回转发地址）
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE rejected (code=%d)", replyCode(head))
	}
	var bndIP net.IP
	var bndPort int
	switch head[3] {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, err
		}
		bndIP, bndPort = net.IP(b[:4]), int(binary.BigEndian.Uint16(b[4:]))
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, err
		}
		bndIP, bndPort = net.IP(b[:16]), int(binary.BigEndian.Uint16(b[16:]))
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE bad ATYP %d", head[3])
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	if bndIP.IsUnspecified() {
		// 服务端返回 0.0.0.0：以控制连接的对端地址为准（标准行为）
		if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			bndIP = ra.IP
		}
	}
	relay, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: bndIP, Port: bndPort})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &socksUDPChannel{control: conn, udp: relay}, nil
}

// socksUDPHeader 打包 SOCKS5 UDP 转发头（RSV+FRAG + ATYP + 目标地址 + 端口）
func socksUDPHeader(dst *net.UDPAddr) []byte {
	var out []byte
	out = append(out, 0, 0, 0)
	if ip4 := dst.IP.To4(); ip4 != nil {
		out = append(out, 0x01)
		out = append(out, ip4...)
	} else {
		out = append(out, 0x04)
		out = append(out, dst.IP.To16()...)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(dst.Port))
	out = append(out, port...)
	return out
}

// addrToNetIP 把 gvisor 的 tcpip.Address 转成 net.IP（按地址长度选 v4/v6）
func addrToNetIP(a tcpip.Address) net.IP {
	if a.Len() == 4 {
		b := a.As4()
		return net.IP(b[:])
	}
	b := a.As16()
	return net.IP(b[:])
}

// ------------------------- 适配器网络配置 -------------------------
