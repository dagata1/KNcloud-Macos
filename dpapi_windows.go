package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows DPAPI（Data Protection API）加解密。
//
// 选它而不是自带密钥的对称加密，是因为本地软件无处安放密钥：密钥只要和密文
// 一起躺在磁盘上，加密就退化成编码。DPAPI 的密钥由操作系统按当前用户账户派生
// 并由 Windows 保管，程序本身拿不到，也就无从泄漏。
//
// 代价是密文与「这台机器上的这个 Windows 用户」绑定：配置文件复制到别的机器
// 或别的账户下就解不开。对登录凭证而言这正是期望的行为。

var (
	modcrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
)

// cryptProtectUIForbidden 禁止 DPAPI 弹出任何交互界面。
// 本程序可能在开机自启、托盘后台等没有前台窗口的场景下读写凭证，
// 一旦弹窗会直接卡死调用。
const cryptProtectUIForbidden = 0x1

// dataBlob 对应 Win32 的 DATA_BLOB 结构。
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newDataBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// bytes 把 DPAPI 返回的缓冲区复制到 Go 内存。
// 必须复制：原缓冲区由 LocalAlloc 分配，随后会被 LocalFree 释放。
func (b dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b dataBlob) free() {
	if b.pbData != nil {
		windows.LocalFree(windows.Handle(unsafe.Pointer(b.pbData)))
	}
}

// protectData 用当前 Windows 用户的 DPAPI 密钥加密。
func protectData(plain, entropy []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	in := newDataBlob(plain)
	ent := newDataBlob(entropy)
	var out dataBlob

	var entPtr *dataBlob
	if len(entropy) > 0 {
		entPtr = &ent
	}

	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // szDataDescr：不写描述，避免把用途信息留在密文里
		uintptr(unsafe.Pointer(entPtr)),
		0, // pvReserved
		0, // pPromptStruct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	// LazyProc.Call 不像 syscall.Syscall 那样享有「uintptr 参数中的指针保持存活」
	// 的编译器豁免，必须显式 KeepAlive，否则 GC 可能在调用期间回收这些缓冲区。
	runtime.KeepAlive(plain)
	runtime.KeepAlive(entropy)
	runtime.KeepAlive(in)
	runtime.KeepAlive(ent)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer out.free()
	return out.bytes(), nil
}

// protectDataOpen 解密 protectData 的产物。
// 命名上与 protectData 配对，避免与 Win32 的 CryptUnprotectData 混淆。
func protectDataOpen(enc, entropy []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, nil
	}
	in := newDataBlob(enc)
	ent := newDataBlob(entropy)
	var out dataBlob

	var entPtr *dataBlob
	if len(entropy) > 0 {
		entPtr = &ent
	}

	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // ppszDataDescr：不需要取回描述
		uintptr(unsafe.Pointer(entPtr)),
		0, // pvReserved
		0, // pPromptStruct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	// LazyProc.Call 不像 syscall.Syscall 那样享有「uintptr 参数中的指针保持存活」
	// 的编译器豁免，必须显式 KeepAlive，否则 GC 可能在调用期间回收这些缓冲区。
	runtime.KeepAlive(enc)
	runtime.KeepAlive(entropy)
	runtime.KeepAlive(in)
	runtime.KeepAlive(ent)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer out.free()
	return out.bytes(), nil
}
