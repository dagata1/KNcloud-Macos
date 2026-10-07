package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// secretPrefix 标记该字段已加密。
//
// 带版本号是为了将来更换加密方式时仍能识别旧格式：解密侧按前缀分派，
// 老配置不会因为升级而变成一串无法解析的乱码。
const secretPrefix = "dpapi:v1:"

// secretEntropy 是参与加解密的应用固有熵值。
//
// 它不是密钥（DPAPI 的密钥由 Windows 按当前用户派生），作用是把密文绑定到
// 本应用：别的程序即便以同一个 Windows 用户身份运行，缺少这段熵也无法解开。
var secretEntropy = []byte("KNcloud-WIN/account-token/v1")

// encodeSecret 把敏感字符串加密成可落盘的形式。
// 空串原样返回，不产生无谓的密文。
func encodeSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	enc, err := protectData([]byte(plain), secretEntropy)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt credential: %w", err)
	}
	return secretPrefix + base64.StdEncoding.EncodeToString(enc), nil
}

// decodeSecret 还原落盘的敏感字符串。
//
// 不带前缀的一律视为旧版明文凭证：原样返回，下一次保存时会自动写成密文。
// 这条兼容路径是必要的，否则老用户升级后会被登出。
func decodeSecret(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, secretPrefix) {
		// 旧版明文，交由调用方在下次保存时完成迁移
		return stored, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("credential is corrupted: %w", err)
	}
	plain, err := protectDataOpen(raw, secretEntropy)
	if err != nil {
		// 配置被复制到其它机器或其它 Windows 账户时必然走到这里：
		// DPAPI 密钥与用户绑定，换个身份就解不开。
		return "", fmt.Errorf("failed to decrypt credential (config may come from another machine or user): %w", err)
	}
	return string(plain), nil
}

// isEncryptedSecret 判断落盘值是否已是密文，供测试与迁移判断使用。
func isEncryptedSecret(stored string) bool {
	return strings.HasPrefix(stored, secretPrefix)
}
