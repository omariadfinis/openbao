// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func (h *harness) register(entity string, data map[string]any) string {
	h.t.Helper()
	return h.ok(entity, logical.UpdateOperation, "register", data).Data["uid"].(string)
}

func (h *harness) attributes(entity, uid string) map[string]any {
	h.t.Helper()
	return h.ok(entity, logical.ReadOperation, "attributes/"+uid, nil).Data["attributes"].(map[string]any)
}

func (h *harness) stateOf(entity, uid string) string {
	h.t.Helper()
	return h.attributes(entity, uid)[AttrState].([]string)[0]
}

func TestRegister_SymmetricKey(t *testing.T) {
	h := newHarness(t)
	material := make([]byte, 32)
	_, _ = rand.Read(material)

	uid := h.register("alice", map[string]any{
		"object_type": TypeSymmetricKey,
		"material":    b64(material),
		"attributes": map[string]any{
			AttrName:                   "master-key",
			AttrObjectGroup:            "mysql",
			AttrCryptographicUsageMask: "12",
		},
	})

	attrs := h.attributes("alice", uid)
	require.Equal(t, []string{StatePreActive}, attrs[AttrState])
	require.Equal(t, []string{AlgAES}, attrs[AttrCryptographicAlgorithm])
	require.Equal(t, []string{"256"}, attrs[AttrCryptographicLength])
	require.Equal(t, []string{"master-key"}, attrs[AttrName])
	require.Equal(t, []string{"mysql"}, attrs[AttrObjectGroup])

	got := h.ok("alice", logical.ReadOperation, "get/"+uid, nil)
	require.Equal(t, material, unb64(t, got.Data["key"]))
	require.Equal(t, FormatRaw, got.Data["format"])

	// A registered AES key works like a generated one.
	h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
	enc := h.encrypt("alice", uid, []byte("hello"), nil)
	dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+uid, decryptArgs(enc, nil))
	require.Equal(t, []byte("hello"), unb64(t, dec.Data["data"]))

	t.Run("validation", func(t *testing.T) {
		h.fails(ReasonMissingData, "alice", logical.UpdateOperation, "register", map[string]any{"object_type": TypeSymmetricKey})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypeSymmetricKey, "material": b64(make([]byte, 15)),
		})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypeSymmetricKey, "material": b64(material),
			"attributes": map[string]any{AttrCryptographicLength: "128"},
		})
		h.fails(ReasonKeyFormatNotSupported, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypeSymmetricKey, "material": b64(material), "format": FormatPKCS8,
		})
		h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": "certificate", "material": b64(material),
		})
	})

	t.Run("HMAC key", func(t *testing.T) {
		hm := h.register("alice", map[string]any{
			"object_type": TypeSymmetricKey, "material": b64(make([]byte, 32)),
			"attributes": map[string]any{AttrCryptographicAlgorithm: "HMAC-SHA256"},
		})
		require.Equal(t, []string{AlgHMACSHA256}, h.attributes("alice", hm)[AttrCryptographicAlgorithm])
	})
}

func TestRegister_SecretData(t *testing.T) {
	h := newHarness(t)
	secret := []byte("s3cr3t-passw0rd")

	uid := h.register("alice", map[string]any{
		"object_type": TypeSecretData,
		"material":    b64(secret),
		"secret_type": "password",
		"attributes":  map[string]any{AttrName: "db-password", AttrObjectGroup: "percona"},
	})

	attrs := h.attributes("alice", uid)
	require.Equal(t, []string{TypeSecretData}, attrs[AttrObjectType])
	require.NotContains(t, attrs, AttrCryptographicAlgorithm)

	got := h.ok("alice", logical.ReadOperation, "get/"+uid, nil)
	require.Equal(t, secret, unb64(t, got.Data["key"]))
	require.Equal(t, "password", got.Data["secret_type"])

	// Secret data is not a cipher key.
	h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
	h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "encrypt/"+uid, map[string]any{"data": b64([]byte("x"))})

	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "register", map[string]any{
		"object_type": TypeSecretData, "material": b64(secret), "secret_type": "other",
	})

	// Located by type and group, the way a keyring enumerates its entries.
	found := h.ok("alice", logical.UpdateOperation, "locate", map[string]any{
		"filters": []string{AttrObjectType + "=" + TypeSecretData, AttrObjectGroup + "=percona"},
	})
	require.Equal(t, []string{uid}, found.Data["uids"])
}

func TestRegister_OpaqueObject(t *testing.T) {
	h := newHarness(t)
	blob := []byte{0, 1, 2, 3, 0xff}
	uid := h.register("alice", map[string]any{"object_type": TypeOpaqueObject, "material": b64(blob)})
	require.Equal(t, blob, unb64(t, h.ok("alice", logical.ReadOperation, "get/"+uid, nil).Data["key"]))
}

func TestRegister_AsymmetricKeys(t *testing.T) {
	h := newHarness(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pkcs8RSA, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pkcs1RSA := x509.MarshalPKCS1PrivateKey(rsaKey)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	rsaPub, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)

	t.Run("RSA private key in PKCS #8 and PKCS #1", func(t *testing.T) {
		for format, der := range map[string][]byte{FormatPKCS8: pkcs8RSA, FormatPKCS1: pkcs1RSA} {
			uid := h.register("alice", map[string]any{"object_type": TypePrivateKey, "material": b64(der), "format": format})
			attrs := h.attributes("alice", uid)
			require.Equal(t, []string{AlgRSA}, attrs[AttrCryptographicAlgorithm], format)
			require.Equal(t, []string{"2048"}, attrs[AttrCryptographicLength], format)

			// Returned as PKCS #8 by default, and convertible to PKCS #1.
			require.Equal(t, pkcs8RSA, unb64(t, h.ok("alice", logical.ReadOperation, "get/"+uid, nil).Data["key"]))
			got := h.ok("alice", logical.ReadOperation, "get/"+uid, map[string]any{"format": FormatPKCS1})
			require.Equal(t, pkcs1RSA, unb64(t, got.Data["key"]))
		}
	})

	t.Run("EC private key", func(t *testing.T) {
		uid := h.register("alice", map[string]any{"object_type": TypePrivateKey, "material": b64(ecDER), "format": FormatECPrivateKey})
		attrs := h.attributes("alice", uid)
		require.Equal(t, []string{AlgECDSA}, attrs[AttrCryptographicAlgorithm])
		require.Equal(t, []string{"384"}, attrs[AttrCryptographicLength])
		got := h.ok("alice", logical.ReadOperation, "get/"+uid, map[string]any{"format": FormatECPrivateKey})
		require.Equal(t, ecDER, unb64(t, got.Data["key"]))
	})

	t.Run("public key", func(t *testing.T) {
		uid := h.register("alice", map[string]any{"object_type": TypePublicKey, "material": b64(rsaPub)})
		require.Equal(t, rsaPub, unb64(t, h.ok("alice", logical.ReadOperation, "get/"+uid, nil).Data["key"]))
		got := h.ok("alice", logical.ReadOperation, "get/"+uid, map[string]any{"format": FormatPKCS1})
		require.Equal(t, x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey), unb64(t, got.Data["key"]))
		h.fails(ReasonKeyFormatNotSupported, "alice", logical.ReadOperation, "get/"+uid, map[string]any{"format": FormatPKCS8})
	})

	t.Run("validation", func(t *testing.T) {
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypePrivateKey, "material": b64([]byte("not a key")),
		})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypePrivateKey, "material": b64(pkcs8RSA),
			"attributes": map[string]any{AttrCryptographicAlgorithm: AlgECDSA},
		})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypePrivateKey, "material": b64(pkcs8RSA),
			"attributes": map[string]any{AttrCryptographicLength: "4096"},
		})
		h.fails(ReasonKeyFormatNotSupported, "alice", logical.UpdateOperation, "register", map[string]any{
			"object_type": TypePrivateKey, "material": b64(pkcs8RSA), "format": "jwk",
		})
	})
}

func TestRegister_ActivationDate(t *testing.T) {
	h := newHarness(t)
	material := b64(make([]byte, 16))
	register := func(date time.Time) string {
		return h.register("alice", map[string]any{
			"object_type": TypeSymmetricKey, "material": material,
			"attributes": map[string]any{AttrActivationDate: date.UTC().Format(time.RFC3339)},
		})
	}
	require.Equal(t, StateActive, h.stateOf("alice", register(time.Now().Add(-time.Hour))))
	require.Equal(t, StatePreActive, h.stateOf("alice", register(time.Now().Add(time.Hour))))
}

func TestCustomAttributes(t *testing.T) {
	h := newHarness(t)
	uid := h.create("alice", map[string]any{"attributes": map[string]any{"x-owner": "team-a", "y-tier": []any{"gold", "pci"}}})

	attrs := h.attributes("alice", uid)
	require.Equal(t, []string{"team-a"}, attrs["x-owner"])
	require.Equal(t, []string{"gold", "pci"}, attrs["y-tier"])

	path := "attributes/" + uid
	h.ok("alice", logical.UpdateOperation, path, map[string]any{"action": "add", "name": "x-owner", "value": "team-b"})
	h.ok("alice", logical.UpdateOperation, path, map[string]any{"action": "modify", "name": "y-tier", "value": "silver", "index": 0})
	h.ok("alice", logical.UpdateOperation, path, map[string]any{"action": "delete", "name": "y-tier", "index": 1})
	attrs = h.attributes("alice", uid)
	require.Equal(t, []string{"team-a", "team-b"}, attrs["x-owner"])
	require.Equal(t, []string{"silver"}, attrs["y-tier"])

	// Custom attributes are searchable.
	found := h.ok("alice", logical.UpdateOperation, "locate", map[string]any{"filters": []string{"x-owner=team-b"}})
	require.Equal(t, []string{uid}, found.Data["uids"])

	h.ok("alice", logical.UpdateOperation, path, map[string]any{"action": "delete", "name": "y-tier"})
	require.NotContains(t, h.attributes("alice", uid), "y-tier")
}

func TestCreate_HMACKey(t *testing.T) {
	h := newHarness(t)
	uid := h.create("alice", map[string]any{"algorithm": AlgHMACSHA256, "length": 256, "usage_mask": int(UsageMACGenerate | UsageMACVerify)})
	attrs := h.attributes("alice", uid)
	require.Equal(t, []string{AlgHMACSHA256}, attrs[AttrCryptographicAlgorithm])
	require.Equal(t, []string{"256"}, attrs[AttrCryptographicLength])

	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "create", map[string]any{"algorithm": AlgHMACSHA256, "length": 64})
	h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "create", map[string]any{"algorithm": "hmac-md5", "length": 256})
}

func TestCreateKeyPair(t *testing.T) {
	h := newHarness(t)

	create := func(data map[string]any) (priv, pub string) {
		resp := h.ok("alice", logical.UpdateOperation, "create-keypair", data)
		return resp.Data["private_uid"].(string), resp.Data["public_uid"].(string)
	}

	t.Run("RSA with per-key attributes", func(t *testing.T) {
		priv, pub := create(map[string]any{
			"attributes":         map[string]any{AttrCryptographicAlgorithm: AlgRSA, AttrCryptographicLength: "2048", AttrObjectGroup: "tls"},
			"private_attributes": map[string]any{AttrName: "signer-private", AttrCryptographicUsageMask: "1"},
			"public_attributes":  map[string]any{AttrName: "signer-public", AttrCryptographicUsageMask: "2"},
		})
		require.NotEqual(t, priv, pub)

		pa, ba := h.attributes("alice", priv), h.attributes("alice", pub)
		require.Equal(t, []string{TypePrivateKey}, pa[AttrObjectType])
		require.Equal(t, []string{TypePublicKey}, ba[AttrObjectType])
		require.Equal(t, []string{"signer-private"}, pa[AttrName])
		require.Equal(t, []string{"signer-public"}, ba[AttrName])
		require.Equal(t, []string{"1"}, pa[AttrCryptographicUsageMask])
		require.Equal(t, []string{"2"}, ba[AttrCryptographicUsageMask])
		require.Equal(t, []string{"tls"}, pa[AttrObjectGroup])
		require.Equal(t, []string{"tls"}, ba[AttrObjectGroup])
		require.Equal(t, []string{LinkPublicKey + ":" + pub}, pa[AttrLink])
		require.Equal(t, []string{LinkPrivateKey + ":" + priv}, ba[AttrLink])

		// The two halves belong together.
		privKey, err := x509.ParsePKCS8PrivateKey(unb64(t, h.ok("alice", logical.ReadOperation, "get/"+priv, nil).Data["key"]))
		require.NoError(t, err)
		pubKey, err := x509.ParsePKIXPublicKey(unb64(t, h.ok("alice", logical.ReadOperation, "get/"+pub, nil).Data["key"]))
		require.NoError(t, err)
		require.True(t, privKey.(*rsa.PrivateKey).PublicKey.Equal(pubKey))
	})

	t.Run("ECDSA", func(t *testing.T) {
		priv, _ := create(map[string]any{"attributes": map[string]any{AttrCryptographicAlgorithm: AlgECDSA, AttrCryptographicLength: "256"}})
		require.Equal(t, []string{"256"}, h.attributes("alice", priv)[AttrCryptographicLength])
	})

	t.Run("validation", func(t *testing.T) {
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes": map[string]any{AttrCryptographicAlgorithm: AlgRSA, AttrCryptographicLength: "1000"},
		})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes": map[string]any{AttrCryptographicAlgorithm: AlgECDSA, AttrCryptographicLength: "255"},
		})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes": map[string]any{AttrCryptographicAlgorithm: AlgRSA},
		})
		h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes": map[string]any{AttrCryptographicAlgorithm: "dsa", AttrCryptographicLength: "2048"},
		})
	})

	t.Run("nothing is stored when one half is invalid", func(t *testing.T) {
		before := h.ok("alice", logical.UpdateOperation, "locate", nil).Data["located_items"]
		h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes":        map[string]any{AttrCryptographicAlgorithm: AlgECDSA, AttrCryptographicLength: "256"},
			"public_attributes": map[string]any{"Archive Date": "x"},
		})
		require.Equal(t, before, h.ok("alice", logical.UpdateOperation, "locate", nil).Data["located_items"])
	})
}

// keyPair creates an RSA or EC pair whose halves may sign and verify.
func (h *harness) keyPair(alg string, bits int) (priv, pub string) {
	h.t.Helper()
	resp := h.ok("alice", logical.UpdateOperation, "create-keypair", map[string]any{
		"attributes":         map[string]any{AttrCryptographicAlgorithm: alg, AttrCryptographicLength: itoa(bits)},
		"private_attributes": map[string]any{AttrCryptographicUsageMask: itoa(int(UsageSign))},
		"public_attributes":  map[string]any{AttrCryptographicUsageMask: itoa(int(UsageVerify))},
	})
	priv, pub = resp.Data["private_uid"].(string), resp.Data["public_uid"].(string)
	h.ok("alice", logical.UpdateOperation, "activate/"+priv, nil)
	h.ok("alice", logical.UpdateOperation, "activate/"+pub, nil)
	return priv, pub
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestSignVerify(t *testing.T) {
	h := newHarness(t)
	msg := []byte("sign this")

	sign := func(uid string, extra map[string]any) []byte {
		data := map[string]any{"data": b64(msg)}
		for k, v := range extra {
			data[k] = v
		}
		return unb64(t, h.ok("alice", logical.UpdateOperation, "sign/"+uid, data).Data["signature"])
	}
	verify := func(uid string, sig []byte, extra map[string]any) bool {
		data := map[string]any{"data": b64(msg), "signature": b64(sig)}
		for k, v := range extra {
			data[k] = v
		}
		return h.ok("alice", logical.UpdateOperation, "verify/"+uid, data).Data["valid"].(bool)
	}

	t.Run("RSA PKCS #1 v1.5, checked against Go's own verifier", func(t *testing.T) {
		priv, pub := h.keyPair(AlgRSA, 2048)
		sig := sign(priv, nil)

		pubKey, err := x509.ParsePKIXPublicKey(unb64(t, h.ok("alice", logical.ReadOperation, "get/"+pub, nil).Data["key"]))
		require.NoError(t, err)
		sum := sha256.Sum256(msg)
		require.NoError(t, rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sig))

		require.True(t, verify(pub, sig, nil))
		require.False(t, verify(pub, sig, map[string]any{"data": b64([]byte("tampered"))}))
		require.False(t, verify(pub, sig, map[string]any{"hash": "sha384"}))
	})

	t.Run("RSA PSS", func(t *testing.T) {
		priv, pub := h.keyPair(AlgRSA, 2048)
		sig := sign(priv, map[string]any{"padding": PaddingPSS})
		require.True(t, verify(pub, sig, map[string]any{"padding": PaddingPSS}))
		require.False(t, verify(pub, sig, nil), "PSS signature must not verify as PKCS #1 v1.5")
	})

	t.Run("ECDSA", func(t *testing.T) {
		for _, bits := range []int{256, 384, 521} {
			priv, pub := h.keyPair(AlgECDSA, bits)
			sig := sign(priv, map[string]any{"hash": "sha384"})
			require.True(t, verify(pub, sig, map[string]any{"hash": "sha384"}), "P-%d", bits)
			require.False(t, verify(pub, sig, map[string]any{"hash": "sha256"}), "P-%d", bits)
		}
	})

	t.Run("a prehashed digest", func(t *testing.T) {
		priv, pub := h.keyPair(AlgRSA, 2048)
		sum := sha256.Sum256(msg)
		sig := sign(priv, map[string]any{"data": b64(sum[:]), "prehashed": true})
		require.True(t, verify(pub, sig, nil), "same signature as signing the message itself")
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "sign/"+priv, map[string]any{"data": b64([]byte("short")), "prehashed": true})
	})

	t.Run("key type, state and usage are enforced", func(t *testing.T) {
		priv, pub := h.keyPair(AlgRSA, 2048)
		data := map[string]any{"data": b64(msg)}

		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "sign/"+pub, data)
		sig := sign(priv, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "verify/"+priv, map[string]any{"data": b64(msg), "signature": b64(sig)})

		h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "sign/"+priv, map[string]any{"data": b64(msg), "hash": "md5"})
		h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "sign/"+priv, map[string]any{"data": b64(msg), "padding": "oaep"})
		h.fails(ReasonMissingData, "alice", logical.UpdateOperation, "verify/"+pub, data)

		// Deactivated keys no longer sign but still verify.
		h.ok("alice", logical.UpdateOperation, "revoke/"+priv, map[string]any{"reason_code": "superseded"})
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "sign/"+priv, data)
		h.ok("alice", logical.UpdateOperation, "revoke/"+pub, map[string]any{"reason_code": "superseded"})
		require.True(t, verify(pub, sig, nil))

		// A key without the usage bit may not be used.
		verifyOnly := h.ok("alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes":         map[string]any{AttrCryptographicAlgorithm: AlgECDSA, AttrCryptographicLength: "256"},
			"private_attributes": map[string]any{AttrCryptographicUsageMask: itoa(int(UsageVerify))},
		}).Data["private_uid"].(string)
		h.ok("alice", logical.UpdateOperation, "activate/"+verifyOnly, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "sign/"+verifyOnly, data)
	})

	t.Run("a pre-active key cannot sign", func(t *testing.T) {
		resp := h.ok("alice", logical.UpdateOperation, "create-keypair", map[string]any{
			"attributes":         map[string]any{AttrCryptographicAlgorithm: AlgRSA, AttrCryptographicLength: "2048"},
			"private_attributes": map[string]any{AttrCryptographicUsageMask: itoa(int(UsageSign))},
		})
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "sign/"+resp.Data["private_uid"].(string), map[string]any{"data": b64(msg)})
	})
}

func TestMAC(t *testing.T) {
	h := newHarness(t)
	mask := int(UsageMACGenerate | UsageMACVerify)
	uid := h.create("alice", map[string]any{"algorithm": AlgHMACSHA256, "length": 256, "usage_mask": mask})
	h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
	msg := []byte("authenticate me")

	key := unb64(t, h.ok("alice", logical.ReadOperation, "get/"+uid, nil).Data["key"])
	want := hmac.New(sha256.New, key)
	want.Write(msg)

	mac := unb64(t, h.ok("alice", logical.UpdateOperation, "mac/"+uid, map[string]any{"data": b64(msg)}).Data["mac"])
	require.Equal(t, want.Sum(nil), mac, "must equal an independent HMAC-SHA256")

	verify := func(data, mac []byte, extra map[string]any) bool {
		args := map[string]any{"data": b64(data), "mac": b64(mac)}
		for k, v := range extra {
			args[k] = v
		}
		return h.ok("alice", logical.UpdateOperation, "mac-verify/"+uid, args).Data["valid"].(bool)
	}
	require.True(t, verify(msg, mac, nil))
	require.True(t, verify(msg, mac, map[string]any{"hash": "sha256"}))
	require.False(t, verify([]byte("other"), mac, nil))
	bad := append([]byte(nil), mac...)
	bad[0] ^= 1
	require.False(t, verify(msg, bad, nil))

	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "mac/"+uid, map[string]any{"data": b64(msg), "hash": "sha512"})
	h.fails(ReasonMissingData, "alice", logical.UpdateOperation, "mac-verify/"+uid, map[string]any{"data": b64(msg)})

	t.Run("only HMAC keys, in the right state, with the right usage", func(t *testing.T) {
		aesKey := h.activeKey("alice")
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "mac/"+aesKey, map[string]any{"data": b64(msg)})

		macOnly := h.create("alice", map[string]any{"algorithm": AlgHMACSHA256, "length": 256, "usage_mask": int(UsageMACVerify)})
		h.ok("alice", logical.UpdateOperation, "activate/"+macOnly, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "mac/"+macOnly, map[string]any{"data": b64(msg)})

		h.ok("alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{"reason_code": "superseded"})
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "mac/"+uid, map[string]any{"data": b64(msg)})
		require.True(t, verify(msg, mac, nil), "a deactivated key can still verify")
	})

	t.Run("every HMAC variant", func(t *testing.T) {
		for _, alg := range []string{AlgHMACSHA1, AlgHMACSHA224, AlgHMACSHA256, AlgHMACSHA384, AlgHMACSHA512} {
			k := h.create("alice", map[string]any{"algorithm": alg, "length": 256, "usage_mask": mask})
			h.ok("alice", logical.UpdateOperation, "activate/"+k, nil)
			m := h.ok("alice", logical.UpdateOperation, "mac/"+k, map[string]any{"data": b64(msg)}).Data["mac"]
			require.True(t, h.ok("alice", logical.UpdateOperation, "mac-verify/"+k, map[string]any{"data": b64(msg), "mac": m}).Data["valid"].(bool), alg)
		}
	})
}

func TestHashAndRandom(t *testing.T) {
	h := newHarness(t)

	sum := sha256.Sum256([]byte("abc"))
	got := h.ok("alice", logical.UpdateOperation, "hash", map[string]any{"data": b64([]byte("abc"))})
	require.Equal(t, sum[:], unb64(t, got.Data["data"]))

	got = h.ok("alice", logical.UpdateOperation, "hash", map[string]any{"data": b64([]byte("abc")), "hash": "sha512"})
	require.Len(t, unb64(t, got.Data["data"]), 64)
	h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "hash", map[string]any{"data": b64([]byte("abc")), "hash": "md5"})

	a := unb64(t, h.ok("alice", logical.UpdateOperation, "random", map[string]any{"length": 32}).Data["data"])
	b := unb64(t, h.ok("alice", logical.UpdateOperation, "random", map[string]any{"length": 32}).Data["data"])
	require.Len(t, a, 32)
	require.NotEqual(t, a, b)
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "random", map[string]any{"length": 0})
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "random", map[string]any{"length": maxRandomBytes + 1})
}

func TestCheck(t *testing.T) {
	h := newHarness(t)
	uid := h.create("alice", map[string]any{"usage_mask": int(UsageEncrypt)})

	h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "check/"+uid, nil)
	h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
	h.ok("alice", logical.UpdateOperation, "check/"+uid, nil)
	h.ok("alice", logical.UpdateOperation, "check/"+uid, map[string]any{"usage_mask": int(UsageEncrypt)})
	h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "check/"+uid, map[string]any{"usage_mask": int(UsageEncrypt | UsageDecrypt)})
	h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "check/"+uid, nil)
}

func TestRekey(t *testing.T) {
	h := newHarness(t)
	old := h.create("alice", map[string]any{
		"name": "volume-key", "usage_mask": int(UsageEncrypt | UsageDecrypt), "description": "v1",
		"attributes": map[string]any{AttrObjectGroup: "prod", "x-env": "blue"},
	})
	h.ok("alice", logical.UpdateOperation, "activate/"+old, nil)
	enc := h.encrypt("alice", old, []byte("written before the rekey"), nil)

	fresh := h.ok("alice", logical.UpdateOperation, "rekey/"+old, nil).Data["uid"].(string)
	require.NotEqual(t, old, fresh)

	oa, na := h.attributes("alice", old), h.attributes("alice", fresh)

	// The new key is a distinct pre-active key with the old one's properties.
	require.Equal(t, []string{StatePreActive}, na[AttrState])
	require.NotEqual(t,
		h.ok("alice", logical.ReadOperation, "get/"+old, nil).Data["key"],
		h.ok("alice", logical.ReadOperation, "get/"+fresh, nil).Data["key"])
	require.Equal(t, oa[AttrCryptographicAlgorithm], na[AttrCryptographicAlgorithm])
	require.Equal(t, oa[AttrCryptographicLength], na[AttrCryptographicLength])
	require.Equal(t, oa[AttrCryptographicUsageMask], na[AttrCryptographicUsageMask])
	require.Equal(t, []string{"prod"}, na[AttrObjectGroup])
	require.Equal(t, []string{"blue"}, na["x-env"])
	require.Equal(t, []string{"v1"}, na[AttrDescription])
	require.NotContains(t, na, AttrName, "a name identifies one object and is not inherited")

	// The two are linked both ways, and the old key is untouched.
	require.Equal(t, []string{LinkReplacement + ":" + fresh}, oa[AttrLink])
	require.Equal(t, []string{LinkReplaced + ":" + old}, na[AttrLink])
	require.Equal(t, []string{StateActive}, oa[AttrState])
	require.Equal(t, []string{"volume-key"}, oa[AttrName])
	dec := h.ok("alice", logical.UpdateOperation, "decrypt/"+old, decryptArgs(enc, nil))
	require.Equal(t, []byte("written before the rekey"), unb64(t, dec.Data["data"]))

	t.Run("a template overrides inherited attributes", func(t *testing.T) {
		next := h.ok("alice", logical.UpdateOperation, "rekey/"+fresh, map[string]any{
			"attributes": map[string]any{AttrName: "volume-key-v3", AttrDescription: "v3"},
		}).Data["uid"].(string)
		attrs := h.attributes("alice", next)
		require.Equal(t, []string{"volume-key-v3"}, attrs[AttrName])
		require.Equal(t, []string{"v3"}, attrs[AttrDescription])
	})

	t.Run("not for asymmetric or destroyed keys, or other owners", func(t *testing.T) {
		priv, _ := h.keyPair(AlgRSA, 2048)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "rekey/"+priv, nil)

		gone := h.create("alice", nil)
		h.ok("alice", logical.UpdateOperation, "destroy/"+gone, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "rekey/"+gone, nil)

		h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "rekey/"+old, nil)
	})
}

func TestRekeyKeyPair(t *testing.T) {
	h := newHarness(t)
	priv, pub := h.keyPair(AlgECDSA, 256)
	h.ok("alice", logical.UpdateOperation, "attributes/"+priv, map[string]any{"action": "add", "name": AttrObjectGroup, "value": "signing"})

	resp := h.ok("alice", logical.UpdateOperation, "rekey-keypair/"+priv, nil)
	newPriv, newPub := resp.Data["private_uid"].(string), resp.Data["public_uid"].(string)
	require.NotEqual(t, priv, newPriv)
	require.NotEqual(t, pub, newPub)

	pa, ba := h.attributes("alice", newPriv), h.attributes("alice", newPub)
	require.Equal(t, []string{"256"}, pa[AttrCryptographicLength])
	require.Equal(t, []string{TypePublicKey}, ba[AttrObjectType])
	require.Equal(t, []string{"signing"}, pa[AttrObjectGroup])
	require.Equal(t, []string{itoa(int(UsageSign))}, pa[AttrCryptographicUsageMask])
	require.Equal(t, []string{itoa(int(UsageVerify))}, ba[AttrCryptographicUsageMask])
	require.Contains(t, pa[AttrLink], LinkPublicKey+":"+newPub)
	require.Contains(t, pa[AttrLink], LinkReplaced+":"+priv)
	require.Contains(t, ba[AttrLink], LinkReplaced+":"+pub)

	// The old pair is kept, linked forward, and can still verify.
	require.Contains(t, h.attributes("alice", priv)[AttrLink], LinkReplacement+":"+newPriv)
	require.Contains(t, h.attributes("alice", pub)[AttrLink], LinkReplacement+":"+newPub)

	h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "rekey-keypair/"+pub, nil)
	h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "rekey-keypair/"+priv, nil)
}
