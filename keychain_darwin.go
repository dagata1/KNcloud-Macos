//go:build darwin

package main

// keychain_darwin.go —— macOS 上替代 DPAPI 的凭证加密。
//
// 随机 256 位密钥存放在登录钥匙串（通用密码，服务名 top.kncloud.macos，
// 账户 config-encryption-key，经 /usr/bin/security 读写），落盘的账户令牌用
// AES-256-GCM 加密，secretEntropy 作为附加认证数据（绑定到本应用）。
// 钥匙串不可用（例如无图形会话的 CI）时退回配置目录下权限 0600 的密钥文件，
// 密文首字节标明所用密钥来源（'K' 钥匙串 / 'F' 文件）。

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const secretPrefix = "keychain:v1:"

const (
	keychainService = "top.kncloud.macos"
	keychainAccount = "config-encryption-key"
)

var (
	secretKeyMu    sync.Mutex
	secretKeyCache = map[byte][]byte{}
)

func runSecurity(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/security", args...).Output()
	return strings.TrimSpace(string(out)), err
}

func decodeKeyHex(s string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != 32 {
		return nil, errors.New("invalid stored key")
	}
	return k, nil
}

func keychainKey(create bool) ([]byte, error) {
	if os.Getenv("KNCLOUD_NO_KEYCHAIN") != "" {
		return nil, errors.New("keychain disabled")
	}
	if out, err := runSecurity("find-generic-password", "-s", keychainService, "-a", keychainAccount, "-w"); err == nil {
		return decodeKeyHex(out)
	}
	if !create {
		return nil, errors.New("key not found in keychain")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if _, err := runSecurity("add-generic-password", "-U", "-s", keychainService, "-a", keychainAccount,
		"-l", "KNcloud", "-w", hex.EncodeToString(k)); err != nil {
		return nil, fmt.Errorf("keychain write failed: %w", err)
	}
	// 回读确认（钥匙串被锁时 add 可能「成功」但读不回）
	out, err := runSecurity("find-generic-password", "-s", keychainService, "-a", keychainAccount, "-w")
	if err != nil {
		return nil, fmt.Errorf("keychain read-back failed: %w", err)
	}
	return decodeKeyHex(out)
}

func fileKeyPath() (string, error) {
	dir, err := appConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".credential-key"), nil
}

func fileKey(create bool) ([]byte, error) {
	p, err := fileKeyPath()
	if err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(p); err == nil {
		return decodeKeyHex(string(b))
	}
	if !create {
		return nil, errors.New("key file not found")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(k)), 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func secretKey(src byte, create bool) ([]byte, error) {
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	if k, ok := secretKeyCache[src]; ok {
		return k, nil
	}
	var k []byte
	var err error
	if src == 'K' {
		k, err = keychainKey(create)
	} else {
		k, err = fileKey(create)
	}
	if err != nil {
		return nil, err
	}
	secretKeyCache[src] = k
	return k, nil
}

func protectData(plain, entropy []byte) ([]byte, error) {
	src := byte('K')
	key, err := secretKey('K', true)
	if err != nil {
		src = 'F'
		if key, err = secretKey('F', true); err != nil {
			return nil, err
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{src}, nonce...)
	return gcm.Seal(out, nonce, plain, entropy), nil
}

func protectDataOpen(enc, entropy []byte) ([]byte, error) {
	if len(enc) < 1+12+16 {
		return nil, errors.New("ciphertext too short")
	}
	key, err := secretKey(enc[0], false)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	return gcm.Open(nil, enc[1:1+ns], enc[1+ns:], entropy)
}
