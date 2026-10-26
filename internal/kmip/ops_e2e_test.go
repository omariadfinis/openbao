package kmip

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"
)

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

const (
	signUsage   = kmip.CryptographicUsageSign
	verifyUsage = kmip.CryptographicUsageVerify
	macUsage    = kmip.CryptographicUsageMACGenerate | kmip.CryptographicUsageMACVerify
)

func TestRegister(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	t.Run("symmetric key, with name and group", func(t *testing.T) {
		material := randBytes(t, 32)
		reg, err := alice.Register().SymmetricKey(kmip.CryptographicAlgorithmAES, aesUsage, material).
			WithName("master").WithAttribute(kmip.AttributeNameObjectGroup, "grp").Exec()
		require.NoError(t, err)

		got, err := alice.Get(reg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.ObjectTypeSymmetricKey, got.ObjectType)
		key, err := got.SymmetricKey()
		require.NoError(t, err)
		require.Equal(t, material, key)

		attrs, err := alice.GetAttributes(reg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		m := attrMap(attrs.Attribute)
		require.Equal(t, []any{kmip.StatePreActive}, m[kmip.AttributeNameState])
		require.Equal(t, []any{int32(256)}, m[kmip.AttributeNameCryptographicLength])
		require.Equal(t, []any{"grp"}, m[kmip.AttributeNameObjectGroup])

		// A registered AES key encrypts like a created one.
		_, err = alice.Activate(reg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		enc, err := alice.Encrypt(reg.UniqueIdentifier).Data([]byte("hi")).Exec()
		require.NoError(t, err)
		require.NotEmpty(t, enc.Data)
	})

	t.Run("secret data", func(t *testing.T) {
		reg, err := alice.Register().Secret(kmip.SecretDataTypePassword, []byte("hunter2")).
			WithName("db-pass").Exec()
		require.NoError(t, err)

		got, err := alice.Get(reg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.ObjectTypeSecretData, got.ObjectType)
		secret, err := got.Secret()
		require.NoError(t, err)
		require.Equal(t, []byte("hunter2"), secret)
	})

	t.Run("RSA and EC private and public keys", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		rsaReg, err := alice.Register().RsaPrivateKey(rsaKey, signUsage).Exec()
		require.NoError(t, err)
		got, err := alice.Get(rsaReg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		back, err := got.RsaPrivateKey()
		require.NoError(t, err)
		require.True(t, rsaKey.Equal(back))

		ecReg, err := alice.Register().EcdsaPrivateKey(ecKey, signUsage).Exec()
		require.NoError(t, err)
		got, err = alice.Get(ecReg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		ecBack, err := got.EcdsaPrivateKey()
		require.NoError(t, err)
		require.True(t, ecKey.Equal(ecBack))

		pubReg, err := alice.Register().RsaPublicKey(&rsaKey.PublicKey, verifyUsage).Exec()
		require.NoError(t, err)
		got, err = alice.Get(pubReg.UniqueIdentifier).Exec()
		require.NoError(t, err)
		pub, err := got.RsaPublicKey()
		require.NoError(t, err)
		require.True(t, rsaKey.PublicKey.Equal(pub))
	})

	t.Run("rejects what it cannot hold", func(t *testing.T) {
		_, err := alice.Register().SymmetricKey(kmip.CryptographicAlgorithmAES, aesUsage, randBytes(t, 15)).Exec()
		requireReason(t, err, kmip.ResultReasonInvalidField)

		_, err = alice.Register().SymmetricKey(kmip.CryptographicAlgorithm3DES, aesUsage, randBytes(t, 24)).Exec()
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)

		_, err = alice.Register().PemCertificate([]byte(testCertPEM)).Exec()
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
	})
}

const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

func TestCreateKeyPairAndSign(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	msg := []byte("a message to sign")

	activate := func(ids ...string) {
		for _, id := range ids {
			_, err := alice.Activate(id).Exec()
			require.NoError(t, err)
		}
	}

	t.Run("RSA", func(t *testing.T) {
		pair, err := alice.CreateKeyPair().RSA(2048, signUsage, verifyUsage).Exec()
		require.NoError(t, err)
		priv, pub := pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier
		require.NotEqual(t, priv, pub)
		activate(priv, pub)

		// The halves are linked, both ways.
		pa, err := alice.GetAttributes(priv, kmip.AttributeNameLink, kmip.AttributeNameObjectType).Exec()
		require.NoError(t, err)
		m := attrMap(pa.Attribute)
		require.Equal(t, []any{kmip.ObjectTypePrivateKey}, m[kmip.AttributeNameObjectType])
		require.Equal(t, []any{kmip.Link{LinkType: kmip.LinkTypePublicKeyLink, LinkedObjectIdentifier: pub}}, m[kmip.AttributeNameLink])

		// Signed by the server with PKCS #1 v1.5 + SHA-256 by default, and
		// accepted by Go's verifier using the public key fetched with Get.
		sig, err := alice.Sign(priv).Data(msg).Exec()
		require.NoError(t, err)
		got, err := alice.Get(pub).Exec()
		require.NoError(t, err)
		pubKey, err := got.RsaPublicKey()
		require.NoError(t, err)
		sum := sha256.Sum256(msg)
		require.NoError(t, rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sum[:], sig.SignatureData))

		verify, err := alice.SignatureVerify(pub).Data(msg).Signature(sig.SignatureData).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.ValidityIndicatorValid, verify.ValidityIndicator)

		bad, err := alice.SignatureVerify(pub).Data([]byte("other")).Signature(sig.SignatureData).Exec()
		require.NoError(t, err, "an invalid signature is a result, not an error")
		require.Equal(t, kmip.ValidityIndicatorInvalid, bad.ValidityIndicator)
	})

	t.Run("RSA-PSS selected through the signature algorithm", func(t *testing.T) {
		pair, err := alice.CreateKeyPair().RSA(2048, signUsage, verifyUsage).Exec()
		require.NoError(t, err)
		activate(pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier)

		params := kmip.CryptographicParameters{
			DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmRSASSA_PSS,
			HashingAlgorithm:          kmip.HashingAlgorithmSHA_384,
		}
		sig, err := alice.Sign(pair.PrivateKeyUniqueIdentifier).WithCryptographicParameters(params).Data(msg).Exec()
		require.NoError(t, err)

		verify, err := alice.SignatureVerify(pair.PublicKeyUniqueIdentifier).WithCryptographicParameters(params).
			Data(msg).Signature(sig.SignatureData).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.ValidityIndicatorValid, verify.ValidityIndicator)

		// The same signature is not a PKCS #1 v1.5 signature.
		plain, err := alice.SignatureVerify(pair.PublicKeyUniqueIdentifier).WithCryptographicParameters(kmip.CryptographicParameters{
			DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmSHA_384WithRSAEncryption,
		}).Data(msg).Signature(sig.SignatureData).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.ValidityIndicatorInvalid, plain.ValidityIndicator)
	})

	t.Run("ECDSA, verified by Go", func(t *testing.T) {
		pair, err := alice.CreateKeyPair().ECDSA(kmip.RecommendedCurveP_256, signUsage, verifyUsage).Exec()
		require.NoError(t, err)
		activate(pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier)

		params := kmip.CryptographicParameters{DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmECDSAWithSHA256}
		sig, err := alice.Sign(pair.PrivateKeyUniqueIdentifier).WithCryptographicParameters(params).Data(msg).Exec()
		require.NoError(t, err)

		got, err := alice.Get(pair.PublicKeyUniqueIdentifier).Exec()
		require.NoError(t, err)
		pub, err := got.EcdsaPublicKey()
		require.NoError(t, err)
		sum := sha256.Sum256(msg)
		require.True(t, ecdsa.VerifyASN1(pub, sum[:], sig.SignatureData))
	})

	t.Run("a digest instead of data", func(t *testing.T) {
		pair, err := alice.CreateKeyPair().RSA(2048, signUsage, verifyUsage).Exec()
		require.NoError(t, err)
		activate(pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier)

		sum := sha256.Sum256(msg)
		sig, err := alice.Sign(pair.PrivateKeyUniqueIdentifier).DigestedData(sum[:]).Exec()
		require.NoError(t, err)
		verify, err := alice.SignatureVerify(pair.PublicKeyUniqueIdentifier).Data(msg).Signature(sig.SignatureData).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.ValidityIndicatorValid, verify.ValidityIndicator)
	})

	t.Run("refusals", func(t *testing.T) {
		pair, err := alice.CreateKeyPair().RSA(2048, signUsage, verifyUsage).Exec()
		require.NoError(t, err)
		priv, pub := pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier

		// Pre-active keys do not sign.
		_, err = alice.Sign(priv).Data(msg).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)
		activate(priv, pub)

		_, err = alice.Sign(pub).Data(msg).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)

		_, err = alice.Sign(priv).WithCryptographicParameters(kmip.CryptographicParameters{
			DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmSHA_1WithRSAEncryption,
		}).Data(msg).Exec()
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)

		_, err = alice.CreateKeyPair().RSA(1000, signUsage, verifyUsage).Exec()
		requireReason(t, err, kmip.ResultReasonInvalidField)

		bob := env.client(t, "bob")
		_, err = bob.Sign(priv).Data(msg).Exec()
		requireReason(t, err, kmip.ResultReasonItemNotFound)
	})
}

func TestMACOverKMIP(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	ctx := context.Background()
	msg := []byte("authenticate this")

	created, err := alice.Create().Object(kmip.ObjectTypeSymmetricKey).
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmHMACSHA256).
		WithAttribute(kmip.AttributeNameCryptographicLength, int32(256)).
		WithAttribute(kmip.AttributeNameCryptographicUsageMask, macUsage).Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier
	_, err = alice.Activate(uid).Exec()
	require.NoError(t, err)

	// The key can be read back and checked against an independent HMAC.
	got, err := alice.Get(uid).Exec()
	require.NoError(t, err)
	key, err := got.SymmetricKey()
	require.NoError(t, err)
	want := hmac.New(sha256.New, key)
	want.Write(msg)

	params := &kmip.CryptographicParameters{CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA256}
	resp, err := alice.Request(ctx, &MACRequestPayload{UniqueIdentifier: uid, CryptographicParameters: params, Data: msg})
	require.NoError(t, err)
	mac := resp.(*MACResponsePayload)
	require.Equal(t, uid, mac.UniqueIdentifier)
	require.Equal(t, want.Sum(nil), mac.MACData)

	verify := func(data, tag []byte) kmip.ValidityIndicator {
		resp, err := alice.Request(ctx, &MACVerifyRequestPayload{UniqueIdentifier: uid, CryptographicParameters: params, Data: data, MACData: tag})
		require.NoError(t, err)
		return resp.(*MACVerifyResponsePayload).ValidityIndicator
	}
	require.Equal(t, kmip.ValidityIndicatorValid, verify(msg, mac.MACData))
	require.Equal(t, kmip.ValidityIndicatorInvalid, verify([]byte("other"), mac.MACData))

	// The algorithm of the request must be the key's.
	_, err = alice.Request(ctx, &MACRequestPayload{
		UniqueIdentifier: uid, Data: msg,
		CryptographicParameters: &kmip.CryptographicParameters{CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA512},
	})
	requireReason(t, err, kmip.ResultReasonInvalidField)

	// An AES key is not a MAC key.
	aesKey := activeAES(t, alice, 256)
	_, err = alice.Request(ctx, &MACRequestPayload{UniqueIdentifier: aesKey, Data: msg})
	requireReason(t, err, kmip.ResultReasonIllegalOperation)
}

func TestHashRNGAndCheck(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	ctx := context.Background()

	t.Run("hash", func(t *testing.T) {
		resp, err := alice.Hash().WithCryptographicParameters(kmip.CryptographicParameters{
			HashingAlgorithm: kmip.HashingAlgorithm(kmip.HashingAlgorithmSHA_256),
		}).Data([]byte("abc")).Exec()
		require.NoError(t, err)
		sum := sha256.Sum256([]byte("abc"))
		require.Equal(t, sum[:], resp.Data)

		_, err = alice.Hash().WithCryptographicParameters(kmip.CryptographicParameters{
			HashingAlgorithm: kmip.HashingAlgorithmMD5,
		}).Data([]byte("abc")).Exec()
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
	})

	t.Run("RNG retrieve", func(t *testing.T) {
		a, err := alice.Request(ctx, &RNGRetrieveRequestPayload{DataLength: 48})
		require.NoError(t, err)
		b, err := alice.Request(ctx, &RNGRetrieveRequestPayload{DataLength: 48})
		require.NoError(t, err)
		require.Len(t, a.(*RNGRetrieveResponsePayload).Data, 48)
		require.NotEqual(t, a.(*RNGRetrieveResponsePayload).Data, b.(*RNGRetrieveResponsePayload).Data)

		_, err = alice.Request(ctx, &RNGRetrieveRequestPayload{DataLength: 0})
		requireReason(t, err, kmip.ResultReasonInvalidField)
	})

	t.Run("check", func(t *testing.T) {
		created, err := alice.Create().AES(256, kmip.CryptographicUsageEncrypt).Exec()
		require.NoError(t, err)
		uid := created.UniqueIdentifier

		_, err = alice.Request(ctx, &CheckRequestPayload{UniqueIdentifier: uid})
		requireReason(t, err, kmip.ResultReasonIllegalOperation) // still pre-active

		_, err = alice.Activate(uid).Exec()
		require.NoError(t, err)
		resp, err := alice.Request(ctx, &CheckRequestPayload{UniqueIdentifier: uid, CryptographicUsageMask: kmip.CryptographicUsageEncrypt})
		require.NoError(t, err)
		require.Equal(t, uid, resp.(*CheckResponsePayload).UniqueIdentifier)

		_, err = alice.Request(ctx, &CheckRequestPayload{UniqueIdentifier: uid, CryptographicUsageMask: kmip.CryptographicUsageDecrypt})
		requireReason(t, err, kmip.ResultReasonIllegalOperation)

		count := int64(5)
		_, err = alice.Request(ctx, &CheckRequestPayload{UniqueIdentifier: uid, UsageLimitsCount: &count})
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
	})
}

func TestRekeyOverKMIP(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	t.Run("symmetric key", func(t *testing.T) {
		old := activeAES(t, alice, 256)
		enc, err := alice.Encrypt(old).Data([]byte("before")).Exec()
		require.NoError(t, err)

		fresh, err := alice.Rekey(old).Exec()
		require.NoError(t, err)
		require.NotEqual(t, old, fresh.UniqueIdentifier)

		oa, err := alice.GetAttributes(old, kmip.AttributeNameLink).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.Link{LinkType: kmip.LinkTypeReplacementObjectLink, LinkedObjectIdentifier: fresh.UniqueIdentifier},
			oa.Attribute[0].AttributeValue)
		na, err := alice.GetAttributes(fresh.UniqueIdentifier, kmip.AttributeNameLink, kmip.AttributeNameState).Exec()
		require.NoError(t, err)
		m := attrMap(na.Attribute)
		require.Equal(t, []any{kmip.Link{LinkType: kmip.LinkTypeReplacedObjectLink, LinkedObjectIdentifier: old}}, m[kmip.AttributeNameLink])
		require.Equal(t, []any{kmip.StatePreActive}, m[kmip.AttributeNameState])

		// Data protected by the old key is still readable with it.
		dec, err := alice.Decrypt(old).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
		require.NoError(t, err)
		require.Equal(t, []byte("before"), dec.Data)

		_, err = alice.Rekey(old).WithOffset(time.Hour).Exec()
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
	})

	t.Run("key pair", func(t *testing.T) {
		pair, err := alice.CreateKeyPair().ECDSA(kmip.RecommendedCurveP_384, signUsage, verifyUsage).Exec()
		require.NoError(t, err)

		next, err := alice.RekeyKeyPair(pair.PrivateKeyUniqueIdentifier).Exec()
		require.NoError(t, err)
		require.NotEqual(t, pair.PrivateKeyUniqueIdentifier, next.PrivateKeyUniqueIdentifier)
		require.NotEqual(t, pair.PublicKeyUniqueIdentifier, next.PublicKeyUniqueIdentifier)

		attrs, err := alice.GetAttributes(next.PrivateKeyUniqueIdentifier, kmip.AttributeNameCryptographicLength, kmip.AttributeNameCryptographicUsageMask).Exec()
		require.NoError(t, err)
		m := attrMap(attrs.Attribute)
		require.Equal(t, []any{int32(384)}, m[kmip.AttributeNameCryptographicLength])
		require.Equal(t, []any{signUsage}, m[kmip.AttributeNameCryptographicUsageMask])
	})
}

func TestCustomAttributesOverKMIP(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	created, err := alice.Create().AES(256, aesUsage).WithAttribute("x-purpose", "backup").Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier

	attrs, err := alice.GetAttributes(uid, "x-purpose").Exec()
	require.NoError(t, err)
	require.Len(t, attrs.Attribute, 1)
	require.Equal(t, "backup", attrs.Attribute[0].AttributeValue.(ttlv.Value).Value)

	_, err = alice.AddAttribute(uid, "x-team", "storage").Exec()
	require.NoError(t, err)
	found, err := alice.Locate().WithAttribute("x-team", "storage").Exec()
	require.NoError(t, err)
	require.Equal(t, []string{uid}, found.UniqueIdentifier)
}

// TestPerconaMySQLKeyringSession replays the sequence of operations the
// Percona Server for MySQL keyring_kmip component performs, as seen in its
// source: Query on connect, Register (AES key or password secret) with a name
// and object group, Activate, enumerate by object type, Get, read the Name
// attribute back, and Revoke then Destroy to delete.
func TestPerconaMySQLKeyringSession(t *testing.T) {
	env := newObjectEnv(t)
	c := env.client(t, "alice")
	require.Equal(t, kmip.V1_4, c.Version())

	const group = "percona-mysql"

	// Connection check.
	q, err := c.Query().Operations().Objects().ServerInformation().Exec()
	require.NoError(t, err)
	require.Contains(t, q.Operations, kmip.OperationRegister)
	require.Contains(t, q.ObjectType, kmip.ObjectTypeSecretData)

	// Store an AES key and a password-type secret.
	aesMaterial := randBytes(t, 32)
	aes, err := c.Register().SymmetricKey(kmip.CryptographicAlgorithmAES, aesUsage, aesMaterial).
		WithName("INNODBKey-uuid-id-1").WithAttribute(kmip.AttributeNameObjectGroup, group).Exec()
	require.NoError(t, err)
	_, err = c.Activate(aes.UniqueIdentifier).Exec()
	require.NoError(t, err)

	secret, err := c.Register().Secret(kmip.SecretDataTypePassword, []byte("s3cr3t")).
		WithName("user-secret-1").WithAttribute(kmip.AttributeNameObjectGroup, group).Exec()
	require.NoError(t, err)
	_, err = c.Activate(secret.UniqueIdentifier).Exec()
	require.NoError(t, err)

	// Load: enumerate keys and secrets by object type, then fetch each one.
	keys, err := c.Locate().WithObjectType(kmip.ObjectTypeSymmetricKey).Exec()
	require.NoError(t, err)
	require.Equal(t, []string{aes.UniqueIdentifier}, keys.UniqueIdentifier)
	secrets, err := c.Locate().WithObjectType(kmip.ObjectTypeSecretData).Exec()
	require.NoError(t, err)
	require.Equal(t, []string{secret.UniqueIdentifier}, secrets.UniqueIdentifier)

	got, err := c.Get(aes.UniqueIdentifier).Exec()
	require.NoError(t, err)
	key, err := got.SymmetricKey()
	require.NoError(t, err)
	require.Equal(t, aesMaterial, key)

	gotSecret, err := c.Get(secret.UniqueIdentifier).Exec()
	require.NoError(t, err)
	value, err := gotSecret.SecretString()
	require.NoError(t, err)
	require.Equal(t, "s3cr3t", value)

	// The key id is the object's Name.
	name, err := c.GetAttributes(aes.UniqueIdentifier, kmip.AttributeNameName).Exec()
	require.NoError(t, err)
	require.Equal(t, kmip.Name{NameValue: "INNODBKey-uuid-id-1", NameType: kmip.NameTypeUninterpretedTextString},
		name.Attribute[0].AttributeValue)

	// Delete: revoke, then destroy.
	for _, id := range []string{aes.UniqueIdentifier, secret.UniqueIdentifier} {
		_, err = c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeUnspecified).
			WithRevocationMessage("Deleting the key").Exec()
		require.NoError(t, err)
		_, err = c.Destroy(id).Exec()
		require.NoError(t, err)
	}
	gone, err := c.Locate().WithObjectType(kmip.ObjectTypeSymmetricKey).WithAttribute(kmip.AttributeNameState, kmip.StateActive).Exec()
	require.NoError(t, err)
	require.Empty(t, gone.UniqueIdentifier)

	// Locating an object type the server does not hold is an empty result.
	certs, err := c.Locate().WithObjectType(kmip.ObjectTypeCertificate).Exec()
	require.NoError(t, err)
	require.Empty(t, certs.UniqueIdentifier)
}

// TestPerconaMongoDBSession replays what Percona Server for MongoDB does when
// it uses KMIP for its master key. It speaks KMIP 1.0: it creates an AES-256
// key, activates it, retrieves the key material, and periodically polls the
// key's state, shutting down if it is not Active.
func TestPerconaMongoDBSession(t *testing.T) {
	env := newObjectEnv(t)
	c := env.client(t, "alice", kmipclient.WithKmipVersions(kmip.V1_0))
	require.Equal(t, kmip.V1_0, c.Version())

	created, err := c.Create().AES(256, aesUsage).Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier

	state := func() kmip.State {
		t.Helper()
		resp, err := c.GetAttributes(uid, kmip.AttributeNameState).Exec()
		require.NoError(t, err)
		return resp.Attribute[0].AttributeValue.(kmip.State)
	}
	require.Equal(t, kmip.StatePreActive, state())

	_, err = c.Activate(uid).Exec()
	require.NoError(t, err)
	require.Equal(t, kmip.StateActive, state())

	got, err := c.Get(uid).Exec()
	require.NoError(t, err)
	key, err := got.SymmetricKey()
	require.NoError(t, err)
	require.Len(t, key, 32)

	// A later start finds the existing key by its identifier.
	again, err := c.Get(uid).Exec()
	require.NoError(t, err)
	sameKey, _ := again.SymmetricKey()
	require.Equal(t, key, sameKey)
}

func TestProtocolVersions(t *testing.T) {
	env := newObjectEnv(t)

	for _, v := range []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4} {
		c := env.client(t, "alice", kmipclient.WithKmipVersions(v))
		require.Equal(t, v, c.Version())

		created, err := c.Create().AES(128, aesUsage).WithName("versioned").Exec()
		require.NoError(t, err, "KMIP %d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
		_, err = c.Activate(created.UniqueIdentifier).Exec()
		require.NoError(t, err)
		got, err := c.Get(created.UniqueIdentifier).Exec()
		require.NoError(t, err)
		key, err := got.SymmetricKey()
		require.NoError(t, err)
		require.Len(t, key, 16)
	}
}

func TestSigningKeyFromX509(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	// A key registered from outside signs like one the server generated.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	reg, err := alice.Register().EcdsaPrivateKey(key, signUsage).Exec()
	require.NoError(t, err)
	_, err = alice.Activate(reg.UniqueIdentifier).Exec()
	require.NoError(t, err)

	msg := []byte("registered key")
	sig, err := alice.Sign(reg.UniqueIdentifier).WithCryptographicParameters(kmip.CryptographicParameters{
		DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmECDSAWithSHA256,
	}).Data(msg).Exec()
	require.NoError(t, err)

	sum := sha256.Sum256(msg)
	require.True(t, ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig.SignatureData))
}

// Operations the server does not implement are refused cleanly with
// Operation Not Supported, whether or not the library can encode them.
func TestUnsupportedOperationsAreRefused(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	ctx := context.Background()
	uid := activeAES(t, alice, 256)

	for name, payload := range map[string]kmip.OperationPayload{
		"Archive":              &payloads.ArchiveRequestPayload{UniqueIdentifier: uid},
		"Recover":              &payloads.RecoverRequestPayload{UniqueIdentifier: uid},
		"Obtain Lease":         &payloads.ObtainLeaseRequestPayload{UniqueIdentifier: uid},
		"Get Usage Allocation": &payloads.GetUsageAllocationRequestPayload{UniqueIdentifier: uid},
		"Export":               &payloads.ExportRequestPayload{UniqueIdentifier: uid},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := alice.Request(ctx, payload)
			requireReason(t, err, kmip.ResultReasonOperationNotSupported)
		})
	}
}
