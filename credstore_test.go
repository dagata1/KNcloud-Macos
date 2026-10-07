package main

import (
	"strings"
	"testing"
)

const testSecret = "eyJ0eXAiOiJKV1QifQ.secret-session-token.abc123"

// TestSecretRoundTrip 走真实 DPAPI：加密后应能原样取回，
// 且落盘形式里不得残留明文。
func TestSecretRoundTrip(t *testing.T) {
	enc, err := encodeSecret(testSecret)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(enc, testSecret) {
		t.Fatal("落盘形式里仍能看到明文凭证")
	}
	if !isEncryptedSecret(enc) {
		t.Fatalf("应带加密前缀，实际 %q", enc)
	}

	got, err := decodeSecret(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != testSecret {
		t.Fatalf("取回结果不一致: %q", got)
	}
}

// TestSecretLegacyPlaintext 老用户升级后不能被登出：
// 旧配置里的明文凭证必须仍可读出，并在下次保存时迁移为密文。
func TestSecretLegacyPlaintext(t *testing.T) {
	if isEncryptedSecret(testSecret) {
		t.Fatal("明文不应被判定为密文")
	}
	got, err := decodeSecret(testSecret)
	if err != nil {
		t.Fatalf("旧版明文应可读: %v", err)
	}
	if got != testSecret {
		t.Fatalf("旧版明文读取结果不一致: %q", got)
	}

	stored, err := encodeSecret(got)
	if err != nil {
		t.Fatalf("迁移加密失败: %v", err)
	}
	if !isEncryptedSecret(stored) {
		t.Fatal("迁移后应为密文")
	}
	back, err := decodeSecret(stored)
	if err != nil || back != testSecret {
		t.Fatalf("迁移后凭证失真: %q %v", back, err)
	}
}

// TestSecretEmptyAndCorrupt 边界：空值不产生密文；
// 损坏或无法解密的内容必须报错，且不返回任何残缺数据。
func TestSecretEmptyAndCorrupt(t *testing.T) {
	if e, err := encodeSecret(""); e != "" || err != nil {
		t.Fatalf("空串应原样返回: %q %v", e, err)
	}
	if d, err := decodeSecret(""); d != "" || err != nil {
		t.Fatalf("空串应原样返回: %q %v", d, err)
	}

	if _, err := decodeSecret(secretPrefix + "!!!not-base64!!!"); err == nil {
		t.Fatal("非法 base64 应报错")
	}
	// 合法 base64 但并非 DPAPI 密文：解密必须失败而不是返回垃圾
	got, err := decodeSecret(secretPrefix + "aGVsbG8gd29ybGQ=")
	if err == nil {
		t.Fatal("无法解密的内容应报错")
	}
	if got != "" {
		t.Fatalf("失败时不得返回任何内容，实际 %q", got)
	}
}

// TestSecretEntropyIsRequired 换掉熵值后不得解开，
// 用于确认密文确实绑定了本应用而非仅绑定 Windows 用户。
func TestSecretEntropyIsRequired(t *testing.T) {
	enc, err := protectData([]byte(testSecret), secretEntropy)
	if err != nil {
		t.Skipf("DPAPI 不可用，跳过: %v", err)
	}
	if _, err := protectDataOpen(enc, []byte("different-entropy")); err == nil {
		t.Fatal("换用不同熵值时必须解密失败")
	}
	back, err := protectDataOpen(enc, secretEntropy)
	if err != nil {
		t.Fatalf("同熵值应能解开: %v", err)
	}
	if string(back) != testSecret {
		t.Fatalf("解密结果不一致: %q", back)
	}
}
