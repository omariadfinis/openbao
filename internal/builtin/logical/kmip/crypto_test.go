// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func unb64(t *testing.T, s any) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(s.(string))
	require.NoError(t, err)
	return out
}

// activeKey creates an Active key that may encrypt and decrypt.
func (h *harness) activeKey(entity string) string {
	h.t.Helper()
	uid := h.create(entity, map[string]any{"usage_mask": int(UsageEncrypt | UsageDecrypt)})
	h.ok(entity, logical.UpdateOperation, "activate/"+uid, nil)
	return uid
}

func (h *harness) encrypt(entity, uid string, plaintext []byte, extra map[string]any) *logical.Response {
	h.t.Helper()
	data := map[string]any{"data": b64(plaintext)}
	for k, v := range extra {
		data[k] = v
	}
	return h.ok(entity, logical.UpdateOperation, "encrypt/"+uid, data)
}

func decryptArgs(enc *logical.Response, extra map[string]any) map[string]any {
	data := map[string]any{
		"data": enc.Data["data"],
		"iv":   enc.Data["iv"],
		"tag":  enc.Data["tag"],
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func TestEncryptDecrypt(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")
	plaintext := []byte("attack at dawn")

	enc := h.encrypt("alice", uid, plaintext, nil)
	require.Len(t, unb64(t, enc.Data["iv"]), 12)
	require.Len(t, unb64(t, enc.Data["tag"]), 16)
	require.Len(t, unb64(t, enc.Data["data"]), len(plaintext))
	require.NotEqual(t, plaintext, unb64(t, enc.Data["data"]))

	dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
	require.Equal(t, plaintext, unb64(t, dec.Data["data"]))

	// A fresh nonce every time, so the same plaintext never repeats.
	again := h.encrypt("alice", uid, plaintext, nil)
	require.NotEqual(t, enc.Data["iv"], again.Data["iv"])
	require.NotEqual(t, enc.Data["data"], again.Data["data"])
}

// The output is standard AES-GCM, so any other implementation interoperates.
func TestEncrypt_StandardGCM(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")

	key := unb64(t, h.ok("alice", logical.ReadOperation, "get/"+uid, nil).Data["key"])
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	enc := h.encrypt("alice", uid, []byte("interop"), map[string]any{"aad": b64([]byte("header"))})
	sealed := append(unb64(t, enc.Data["data"]), unb64(t, enc.Data["tag"])...)
	got, err := gcm.Open(nil, unb64(t, enc.Data["iv"]), sealed, []byte("header"))
	require.NoError(t, err)
	require.Equal(t, []byte("interop"), got)

	// And data sealed elsewhere decrypts here.
	nonce := make([]byte, 12)
	nonce[0] = 7
	ext := gcm.Seal(nil, nonce, []byte("from outside"), nil)
	dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, map[string]any{
		"data": b64(ext[:len(ext)-16]),
		"iv":   b64(nonce),
		"tag":  b64(ext[len(ext)-16:]),
	})
	require.Equal(t, []byte("from outside"), unb64(t, dec.Data["data"]))
}

func TestEncryptDecrypt_AssociatedData(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")

	enc := h.encrypt("alice", uid, []byte("payload"), map[string]any{"aad": b64([]byte("context-a"))})

	ok := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, map[string]any{"aad": b64([]byte("context-a"))}))
	require.Equal(t, []byte("payload"), unb64(t, ok.Data["data"]))

	h.fails(ReasonCryptographicFailure, "alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, map[string]any{"aad": b64([]byte("context-b"))}))
	h.fails(ReasonCryptographicFailure, "alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
}

func TestDecrypt_Tampering(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")
	enc := h.encrypt("alice", uid, []byte("do not touch"), nil)

	flip := func(field string) map[string]any {
		args := decryptArgs(enc, nil)
		raw := unb64(t, args[field])
		raw[0] ^= 0xff
		args[field] = b64(raw)
		return args
	}
	for _, field := range []string{"data", "iv", "tag"} {
		h.fails(ReasonCryptographicFailure, "alice", logical.UpdateOperation, "decrypt/"+uid, flip(field))
	}

	// Another key cannot decrypt it either.
	other := h.activeKey("alice")
	h.fails(ReasonCryptographicFailure, "alice", logical.UpdateOperation, "decrypt/"+other, decryptArgs(enc, nil))
}

func TestDecrypt_Validation(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")
	enc := h.encrypt("alice", uid, []byte("x"), nil)

	h.fails(ReasonMissingData, "alice", logical.UpdateOperation, "decrypt/"+uid, map[string]any{"data": enc.Data["data"]})
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, map[string]any{"iv": b64([]byte("short"))}))
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, map[string]any{"data": "%%%not base64"}))
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, map[string]any{"tag": b64([]byte("tiny"))}))
}

func TestEncrypt_TagLength(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")

	enc := h.encrypt("alice", uid, []byte("short tag"), map[string]any{"tag_length": 12})
	require.Len(t, unb64(t, enc.Data["tag"]), 12)
	dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
	require.Equal(t, []byte("short tag"), unb64(t, dec.Data["data"]))

	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64([]byte("x")), "tag_length": 4})
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64([]byte("x")), "tag_length": 32})
}

func TestCrypto_KeyStateAndUsage(t *testing.T) {
	h := newHarness(t)
	both := int(UsageEncrypt | UsageDecrypt)
	plain := []byte("state matters")

	t.Run("a pre-active key cannot be used", func(t *testing.T) {
		uid := h.create("alice", map[string]any{"usage_mask": both})
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64(plain)})
	})

	t.Run("a deactivated key decrypts but no longer encrypts", func(t *testing.T) {
		uid := h.activeKey("alice")
		enc := h.encrypt("alice", uid, plain, nil)

		h.ok("alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{"reason_code": "superseded"})

		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64(plain)})
		dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
		require.Equal(t, plain, unb64(t, dec.Data["data"]))
	})

	t.Run("a compromised key decrypts but no longer encrypts", func(t *testing.T) {
		uid := h.activeKey("alice")
		enc := h.encrypt("alice", uid, plain, nil)

		h.ok("alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{"reason_code": ReasonKeyCompromise})

		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64(plain)})
		h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
	})

	t.Run("a destroyed key cannot be used", func(t *testing.T) {
		uid := h.activeKey("alice")
		enc := h.encrypt("alice", uid, plain, nil)
		h.ok("alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{"reason_code": "superseded"})
		h.ok("alice", logical.UpdateOperation, "destroy/"+uid, nil)

		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64(plain)})
	})

	t.Run("the usage mask limits what a key may do", func(t *testing.T) {
		encryptOnly := h.create("alice", map[string]any{"usage_mask": int(UsageEncrypt)})
		h.ok("alice", logical.UpdateOperation, "activate/"+encryptOnly, nil)
		enc := h.encrypt("alice", encryptOnly, plain, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "decrypt/"+encryptOnly, decryptArgs(enc, nil))

		decryptOnly := h.create("alice", map[string]any{"usage_mask": int(UsageDecrypt)})
		h.ok("alice", logical.UpdateOperation, "activate/"+decryptOnly, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+decryptOnly, map[string]any{"data": b64(plain)})

		// Sign only (mask bit 1): neither encrypt nor decrypt is permitted.
		signOnly := h.create("alice", map[string]any{"usage_mask": 1})
		h.ok("alice", logical.UpdateOperation, "activate/"+signOnly, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+signOnly, map[string]any{"data": b64(plain)})
	})
}

func TestCrypto_Ownership(t *testing.T) {
	h := newHarness(t)
	uid := h.activeKey("alice")
	enc := h.encrypt("alice", uid, []byte("private"), nil)

	h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64([]byte("x"))})
	h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
}

func TestAESKeySizes(t *testing.T) {
	h := newHarness(t)
	for _, bits := range []int{128, 192, 256} {
		uid := h.create("alice", map[string]any{"length": bits, "usage_mask": int(UsageEncrypt | UsageDecrypt)})
		h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
		enc := h.encrypt("alice", uid, []byte("every size works"), nil)
		dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
		require.Equal(t, []byte("every size works"), unb64(t, dec.Data["data"]), "AES-%d", bits)
	}
}
