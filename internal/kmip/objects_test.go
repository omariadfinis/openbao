package kmip

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/sdk/v2/logical"
	certauth "github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	engine "github.com/openbao/openbao/v2/internal/builtin/logical/kmip"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault"
)

const kmipPolicy = `path "kmip/*" { capabilities = ["create", "read", "update", "list"] }`

type objectEnv struct {
	addr string
	pki  *testPKI
}

// newObjectEnv starts a KMIP server backed by a core with the cert auth
// method and the kmip secrets engine. Clients with the common names "alice",
// "bob" and "carol" are accepted; each becomes a distinct identity.
func newObjectEnv(t *testing.T) *objectEnv {
	t.Helper()
	pki := newTestPKI(t)

	core, _, root := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{"cert": certauth.Factory},
		LogicalBackends:    map[string]logical.Factory{"kmip": engine.Factory},
	})
	write := func(path string, data map[string]any) {
		t.Helper()
		req := logical.TestRequest(t, logical.UpdateOperation, path)
		req.Data = data
		req.ClientToken = root
		resp, err := core.HandleRequest(namespace.RootContext(t.Context()), req)
		require.NoError(t, err)
		require.False(t, resp.IsError(), "%s: %v", path, resp.Error())
	}
	write("sys/auth/cert", map[string]any{"type": "cert"})
	write("sys/mounts/kmip", map[string]any{"type": "kmip"})
	write("sys/policies/acl/kmip", map[string]any{"policy": kmipPolicy})
	write("auth/cert/certs/clients", map[string]any{
		"certificate":          string(pki.caPEM),
		"allowed_common_names": "alice,bob,carol",
		"token_policies":       "kmip",
	})

	dir := t.TempDir()
	srvCert, srvKey := pki.issue(t, "kmip server", x509.ExtKeyUsageServerAuth)
	cfg, err := TLSConfig(
		writeFile(t, dir, "server.pem", srvCert),
		writeFile(t, dir, "server.key", srvKey),
		writeFile(t, dir, "ca.pem", pki.caPEM),
	)
	require.NoError(t, err)

	auth := &Authenticator{Core: core, LoginPath: "auth/cert/login", Role: "clients"}
	h := NewHandler()
	h.Use(AuthMiddleware(auth))
	h.RegisterObjectOperations(auth, "kmip/")

	srv, err := NewServer("127.0.0.1:0", cfg, h)
	require.NoError(t, err)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return &objectEnv{addr: srv.Addr(), pki: pki}
}

func (e *objectEnv) client(t *testing.T, cn string, extra ...kmipclient.Option) *kmipclient.Client {
	t.Helper()
	certPEM, keyPEM := e.pki.issue(t, cn, x509.ExtKeyUsageClientAuth)
	opts := append([]kmipclient.Option{
		kmipclient.WithRootCAPem(e.pki.caPEM),
		kmipclient.WithClientCertPEM(certPEM, keyPEM),
	}, extra...)
	c, err := kmipclient.Dial(e.addr, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

const aesUsage = kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt

func attrMap(attrs []kmip.Attribute) map[kmip.AttributeName][]any {
	m := make(map[kmip.AttributeName][]any)
	for _, a := range attrs {
		m[a.AttributeName] = append(m[a.AttributeName], a.AttributeValue)
	}
	return m
}

func requireReason(t *testing.T, err error, reason kmip.ResultReason) {
	t.Helper()
	require.Error(t, err)
	require.ErrorContains(t, err, ttlv.EnumStr(reason))
}

func TestObjectLifecycle(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	created, err := alice.Create().AES(256, aesUsage).WithName("disk-key").Exec()
	require.NoError(t, err)
	require.Equal(t, kmip.ObjectTypeSymmetricKey, created.ObjectType)
	uid := created.UniqueIdentifier
	require.NotEmpty(t, uid)

	state := func() kmip.State {
		t.Helper()
		resp, err := alice.GetAttributes(uid, kmip.AttributeNameState).Exec()
		require.NoError(t, err)
		return resp.Attribute[0].AttributeValue.(kmip.State)
	}

	t.Run("a new key is pre-active with the requested attributes", func(t *testing.T) {
		require.Equal(t, kmip.StatePreActive, state())

		resp, err := alice.GetAttributes(uid).Exec()
		require.NoError(t, err)
		attrs := attrMap(resp.Attribute)
		require.Equal(t, []any{int32(256)}, attrs[kmip.AttributeNameCryptographicLength])
		require.Equal(t, []any{kmip.CryptographicAlgorithmAES}, attrs[kmip.AttributeNameCryptographicAlgorithm])
		require.Equal(t, []any{aesUsage}, attrs[kmip.AttributeNameCryptographicUsageMask])
		require.Equal(t, []any{kmip.ObjectTypeSymmetricKey}, attrs[kmip.AttributeNameObjectType])
		require.Equal(t, []any{kmip.Name{NameValue: "disk-key", NameType: kmip.NameTypeUninterpretedTextString}}, attrs[kmip.AttributeNameName])
		require.Equal(t, []any{uid}, attrs[kmip.AttributeNameUniqueIdentifier])
		require.Contains(t, attrs, kmip.AttributeNameInitialDate)
	})

	t.Run("get returns the raw key", func(t *testing.T) {
		got, err := alice.Get(uid).Exec()
		require.NoError(t, err)
		require.Equal(t, uid, got.UniqueIdentifier)
		key, err := got.SymmetricKey()
		require.NoError(t, err)
		require.Len(t, key, 32)

		again, err := alice.Get(uid).Exec()
		require.NoError(t, err)
		sameKey, _ := again.SymmetricKey()
		require.Equal(t, key, sameKey)
	})

	t.Run("activate", func(t *testing.T) {
		_, err := alice.Activate(uid).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.StateActive, state())

		_, err = alice.Activate(uid).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)
	})

	t.Run("an active key cannot be destroyed", func(t *testing.T) {
		_, err := alice.Destroy(uid).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)
	})

	t.Run("revoke deactivates with a reason", func(t *testing.T) {
		_, err := alice.Revoke(uid).
			WithRevocationReasonCode(kmip.RevocationReasonCodeSuperseded).
			WithRevocationMessage("rotated").Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.StateDeactivated, state())

		resp, err := alice.GetAttributes(uid, kmip.AttributeNameRevocationReason, kmip.AttributeNameDeactivationDate).Exec()
		require.NoError(t, err)
		attrs := attrMap(resp.Attribute)
		require.Equal(t, []any{kmip.RevocationReason{
			RevocationReasonCode: kmip.RevocationReasonCodeSuperseded,
			RevocationMessage:    "rotated",
		}}, attrs[kmip.AttributeNameRevocationReason])
		require.Contains(t, attrs, kmip.AttributeNameDeactivationDate)
	})

	t.Run("destroy wipes the key but keeps the object", func(t *testing.T) {
		_, err := alice.Destroy(uid).Exec()
		require.NoError(t, err)
		require.Equal(t, kmip.StateDestroyed, state())

		_, err = alice.Get(uid).Exec()
		requireReason(t, err, kmip.ResultReasonKeyValueNotPresent)

		_, err = alice.Destroy(uid).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)
	})
}

func TestKeyCompromise(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	created, err := alice.Create().AES(128, aesUsage).Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier

	_, err = alice.Revoke(uid).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).Exec()
	require.NoError(t, err)

	resp, err := alice.GetAttributes(uid, kmip.AttributeNameState, kmip.AttributeNameCompromiseDate).Exec()
	require.NoError(t, err)
	attrs := attrMap(resp.Attribute)
	require.Equal(t, []any{kmip.StateCompromised}, attrs[kmip.AttributeNameState])
	require.Contains(t, attrs, kmip.AttributeNameCompromiseDate)

	_, err = alice.Destroy(uid).Exec()
	require.NoError(t, err)
	resp, err = alice.GetAttributes(uid, kmip.AttributeNameState).Exec()
	require.NoError(t, err)
	require.Equal(t, kmip.StateDestroyedCompromised, resp.Attribute[0].AttributeValue)
}

func TestAttributeOperations(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	created, err := alice.Create().AES(256, aesUsage).WithName("one").Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier

	names := func() []kmip.Name {
		resp, err := alice.GetAttributes(uid, kmip.AttributeNameName).Exec()
		require.NoError(t, err)
		var out []kmip.Name
		for _, a := range resp.Attribute {
			out = append(out, a.AttributeValue.(kmip.Name))
		}
		return out
	}
	named := func(v string) kmip.Name {
		return kmip.Name{NameValue: v, NameType: kmip.NameTypeUninterpretedTextString}
	}

	added, err := alice.AddAttribute(uid, kmip.AttributeNameName, named("two")).Exec()
	require.NoError(t, err)
	require.Equal(t, named("two"), added.Attribute.AttributeValue)
	require.Equal(t, []kmip.Name{named("one"), named("two")}, names())

	idx := int32(1)
	modified, err := alice.ModifyAttribute(uid, kmip.AttributeNameName, named("deux")).WithIndex(idx).Exec()
	require.NoError(t, err)
	require.Equal(t, named("deux"), modified.Attribute.AttributeValue)
	require.Equal(t, []kmip.Name{named("one"), named("deux")}, names())

	deleted, err := alice.DeleteAttribute(uid, kmip.AttributeNameName).WithIndex(0).Exec()
	require.NoError(t, err)
	require.Equal(t, named("one"), deleted.Attribute.AttributeValue)
	require.Equal(t, []kmip.Name{named("deux")}, names())

	_, err = alice.AddAttribute(uid, kmip.AttributeNameDescription, "scratch volume").Exec()
	require.NoError(t, err)
	_, err = alice.AddAttribute(uid, kmip.AttributeNameDescription, "again").Exec()
	requireReason(t, err, kmip.ResultReasonIllegalOperation)

	// Server-managed attributes cannot be changed by the client.
	_, err = alice.ModifyAttribute(uid, kmip.AttributeNameCryptographicLength, int32(128)).Exec()
	requireReason(t, err, kmip.ResultReasonIllegalOperation)

	list, err := alice.GetAttributeList(uid).Exec()
	require.NoError(t, err)
	require.Contains(t, list.AttributeName, kmip.AttributeNameState)
	require.Contains(t, list.AttributeName, kmip.AttributeNameDescription)
}

func TestLocate(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	one, err := alice.Create().AES(256, aesUsage).WithName("db").Exec()
	require.NoError(t, err)
	two, err := alice.Create().AES(128, aesUsage).WithName("db").Exec()
	require.NoError(t, err)
	three, err := alice.Create().AES(256, aesUsage).WithName("web").Exec()
	require.NoError(t, err)

	_, err = alice.Activate(one.UniqueIdentifier).Exec()
	require.NoError(t, err)

	located := func(l kmipclient.ExecLocate) []string {
		t.Helper()
		resp, err := l.Exec()
		require.NoError(t, err)
		return resp.UniqueIdentifier
	}

	require.ElementsMatch(t, []string{one.UniqueIdentifier, two.UniqueIdentifier},
		located(alice.Locate().WithName("db")))
	require.ElementsMatch(t, []string{one.UniqueIdentifier, three.UniqueIdentifier},
		located(alice.Locate().WithAttribute(kmip.AttributeNameCryptographicLength, int32(256))))
	require.Equal(t, []string{one.UniqueIdentifier},
		located(alice.Locate().WithName("db").WithAttribute(kmip.AttributeNameState, kmip.StateActive)))
	require.Empty(t, located(alice.Locate().WithName("nothing")))
	require.Len(t, located(alice.Locate().WithMaxItems(2)), 2)
	require.Len(t, located(alice.Locate()), 3)
}

func TestIDPlaceholder(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	// Create, Activate and Get in one batch: the later operations name no
	// object and use the one Create produced.
	items, err := alice.Batch(context.Background(),
		&payloads.CreateRequestPayload{
			ObjectType: kmip.ObjectTypeSymmetricKey,
			TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: aesUsage},
			}},
		},
		&payloads.ActivateRequestPayload{},
		&payloads.GetRequestPayload{},
	)
	require.NoError(t, err)
	require.Len(t, items, 3)
	for _, item := range items {
		require.NoError(t, item.Err())
	}

	uid := items[0].ResponsePayload.(*payloads.CreateResponsePayload).UniqueIdentifier
	got := items[2].ResponsePayload.(*payloads.GetResponsePayload)
	require.Equal(t, uid, got.UniqueIdentifier)

	resp, err := alice.GetAttributes(uid, kmip.AttributeNameState).Exec()
	require.NoError(t, err)
	require.Equal(t, kmip.StateActive, resp.Attribute[0].AttributeValue)
}

func TestOwnershipIsolation(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	bob := env.client(t, "bob")

	created, err := alice.Create().AES(256, aesUsage).WithName("alice-only").Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier

	// Bob cannot tell the object exists, let alone use it.
	_, err = bob.Get(uid).Exec()
	requireReason(t, err, kmip.ResultReasonItemNotFound)
	_, err = bob.GetAttributes(uid).Exec()
	requireReason(t, err, kmip.ResultReasonItemNotFound)
	_, err = bob.Activate(uid).Exec()
	requireReason(t, err, kmip.ResultReasonItemNotFound)
	_, err = bob.Destroy(uid).Exec()
	requireReason(t, err, kmip.ResultReasonItemNotFound)

	located, err := bob.Locate().WithName("alice-only").Exec()
	require.NoError(t, err)
	require.Empty(t, located.UniqueIdentifier)

	// Alice still has it, untouched by bob's attempts.
	got, err := alice.Locate().WithName("alice-only").Exec()
	require.NoError(t, err)
	require.Equal(t, []string{uid}, got.UniqueIdentifier)
	resp, err := alice.GetAttributes(uid, kmip.AttributeNameState).Exec()
	require.NoError(t, err)
	require.Equal(t, kmip.StatePreActive, resp.Attribute[0].AttributeValue)
}

func TestCreateValidation(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	_, err := alice.Create().AES(100, aesUsage).Exec()
	requireReason(t, err, kmip.ResultReasonInvalidField)

	_, err = alice.Create().Object(kmip.ObjectTypeCertificate).Exec()
	requireReason(t, err, kmip.ResultReasonFeatureNotSupported)

	_, err = alice.Create().TDES(192, aesUsage).Exec()
	requireReason(t, err, kmip.ResultReasonFeatureNotSupported)

	// An attribute that Create does not accept.
	_, err = alice.Create().AES(256, aesUsage).WithAttribute(kmip.AttributeNameArchiveDate, time.Now()).Exec()
	requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
}

func TestQueryReportsObjectOperations(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	resp, err := alice.Query().Operations().Objects().Exec()
	require.NoError(t, err)
	require.ElementsMatch(t, []kmip.Operation{
		kmip.OperationDiscoverVersions, kmip.OperationQuery,
		kmip.OperationCreate, kmip.OperationGet, kmip.OperationGetAttributes, kmip.OperationGetAttributeList,
		kmip.OperationAddAttribute, kmip.OperationModifyAttribute, kmip.OperationDeleteAttribute,
		kmip.OperationLocate, kmip.OperationActivate, kmip.OperationRevoke, kmip.OperationDestroy,
		kmip.OperationEncrypt, kmip.OperationDecrypt,
		kmip.OperationRegister, kmip.OperationCreateKeyPair, kmip.OperationReKey, kmip.OperationReKeyKeyPair,
		kmip.OperationCheck, kmip.OperationSign, kmip.OperationSignatureVerify,
		kmip.OperationMAC, kmip.OperationMACVerify, kmip.OperationHash, kmip.OperationRNGRetrieve,
	}, resp.Operations)
	require.ElementsMatch(t, []kmip.ObjectType{
		kmip.ObjectTypeSymmetricKey, kmip.ObjectTypeSecretData, kmip.ObjectTypeOpaqueObject,
		kmip.ObjectTypePrivateKey, kmip.ObjectTypePublicKey,
	}, resp.ObjectType)
}

// activeAES creates an Active AES key that may encrypt and decrypt.
func activeAES(t *testing.T, c *kmipclient.Client, bits int) string {
	t.Helper()
	created, err := c.Create().AES(bits, aesUsage).Exec()
	require.NoError(t, err)
	_, err = c.Activate(created.UniqueIdentifier).Exec()
	require.NoError(t, err)
	return created.UniqueIdentifier
}

func TestEncryptDecrypt(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	uid := activeAES(t, alice, 256)
	plaintext := []byte("the quick brown fox")

	enc, err := alice.Encrypt(uid).Data(plaintext).Exec()
	require.NoError(t, err)
	require.Equal(t, uid, enc.UniqueIdentifier)
	require.Len(t, enc.IVCounterNonce, 12)
	require.Len(t, enc.AuthenticatedEncryptionTag, 16)
	require.Len(t, enc.Data, len(plaintext))
	require.NotEqual(t, plaintext, enc.Data)

	dec, err := alice.Decrypt(uid).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
	require.NoError(t, err)
	require.Equal(t, plaintext, dec.Data)

	t.Run("explicit GCM parameters and a shorter tag", func(t *testing.T) {
		params := kmip.CryptographicParameters{
			BlockCipherMode:        kmip.BlockCipherModeGCM,
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			IVLength:               96,
			TagLength:              12,
		}
		enc, err := alice.Encrypt(uid).WithCryptographicParameters(params).Data(plaintext).Exec()
		require.NoError(t, err)
		require.Len(t, enc.AuthenticatedEncryptionTag, 12)

		dec, err := alice.Decrypt(uid).WithCryptographicParameters(params).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
		require.NoError(t, err)
		require.Equal(t, plaintext, dec.Data)
	})

	t.Run("additional authenticated data is bound to the ciphertext", func(t *testing.T) {
		enc, err := alice.Encrypt(uid).WithAAD([]byte("volume-7")).Data(plaintext).Exec()
		require.NoError(t, err)

		decrypt := func(aad []byte) (*payloads.DecryptResponsePayload, error) {
			return alice.Decrypt(uid).WithAAD(aad).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
		}
		ok, err := decrypt([]byte("volume-7"))
		require.NoError(t, err)
		require.Equal(t, plaintext, ok.Data)

		_, err = decrypt([]byte("volume-8"))
		requireReason(t, err, kmip.ResultReasonCryptographicFailure)
	})

	t.Run("tampering is detected", func(t *testing.T) {
		bad := append([]byte(nil), enc.Data...)
		bad[0] ^= 0xff
		_, err := alice.Decrypt(uid).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(bad).Exec()
		requireReason(t, err, kmip.ResultReasonCryptographicFailure)
	})

	t.Run("an IV and tag are required to decrypt", func(t *testing.T) {
		_, err := alice.Decrypt(uid).Data(enc.Data).Exec()
		requireReason(t, err, kmip.ResultReasonMissingData)
	})
}

// The ciphertext is plain AES-GCM, so the key retrieved with Get decrypts it
// with any other implementation, and the reverse.
func TestEncryptDecrypt_Interoperability(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	uid := activeAES(t, alice, 256)

	got, err := alice.Get(uid).Exec()
	require.NoError(t, err)
	key, err := got.SymmetricKey()
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	enc, err := alice.Encrypt(uid).WithAAD([]byte("hdr")).Data([]byte("server to local")).Exec()
	require.NoError(t, err)
	sealed := append(append([]byte(nil), enc.Data...), enc.AuthenticatedEncryptionTag...)
	plain, err := gcm.Open(nil, enc.IVCounterNonce, sealed, []byte("hdr"))
	require.NoError(t, err)
	require.Equal(t, []byte("server to local"), plain)

	nonce := make([]byte, gcm.NonceSize())
	nonce[11] = 1
	ext := gcm.Seal(nil, nonce, []byte("local to server"), nil)
	dec, err := alice.Decrypt(uid).WithIvCounterNonce(nonce).WithAuthTag(ext[len(ext)-16:]).Data(ext[:len(ext)-16]).Exec()
	require.NoError(t, err)
	require.Equal(t, []byte("local to server"), dec.Data)
}

func TestEncrypt_UnsupportedRequests(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	uid := activeAES(t, alice, 256)

	mode := func(m kmip.BlockCipherMode) kmip.CryptographicParameters {
		return kmip.CryptographicParameters{BlockCipherMode: m}
	}

	for _, m := range []kmip.BlockCipherMode{kmip.BlockCipherModeECB, kmip.BlockCipherModeCBC, kmip.BlockCipherModeCTR} {
		_, err := alice.Encrypt(uid).WithCryptographicParameters(mode(m)).Data([]byte("x")).Exec()
		requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
	}

	// The IV is the server's to choose.
	_, err := alice.Encrypt(uid).WithIvCounterNonce(make([]byte, 12)).Data([]byte("x")).Exec()
	requireReason(t, err, kmip.ResultReasonFeatureNotSupported)

	_, err = alice.Encrypt(uid).WithCryptographicParameters(kmip.CryptographicParameters{IVLength: 128}).Data([]byte("x")).Exec()
	requireReason(t, err, kmip.ResultReasonInvalidField)
	_, err = alice.Encrypt(uid).WithCryptographicParameters(kmip.CryptographicParameters{TagLength: 4}).Data([]byte("x")).Exec()
	requireReason(t, err, kmip.ResultReasonInvalidField)

	// Multi-part requests are not supported.
	init := true
	final := false
	_, err = alice.Encrypt(uid).Data([]byte("x")).Exec()
	require.NoError(t, err)
	resp, err := alice.RoundTrip(context.Background(), requestFor(t, alice, &payloads.EncryptRequestPayload{
		UniqueIdentifier: uid, Data: []byte("x"), InitIndicator: &init, FinalIndicator: &final,
	}))
	require.NoError(t, err)
	requireReason(t, resp.BatchItem[0].Err(), kmip.ResultReasonFeatureNotSupported)

	// A client speaking an older protocol cannot receive the tag.
	old := env.client(t, "alice", kmipclient.WithKmipVersions(kmip.V1_2))
	require.Equal(t, kmip.V1_2, old.Version())
	_, err = old.Encrypt(uid).Data([]byte("x")).Exec()
	requireReason(t, err, kmip.ResultReasonFeatureNotSupported)
}

func requestFor(t *testing.T, c *kmipclient.Client, pl kmip.OperationPayload) *kmip.RequestMessage {
	t.Helper()
	msg := kmip.NewRequestMessage(c.Version(), pl)
	return &msg
}

func TestCrypto_LifecycleAndUsageOverKMIP(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")

	t.Run("a pre-active key cannot encrypt", func(t *testing.T) {
		created, err := alice.Create().AES(256, aesUsage).Exec()
		require.NoError(t, err)
		_, err = alice.Encrypt(created.UniqueIdentifier).Data([]byte("x")).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)
	})

	t.Run("a deactivated key still decrypts", func(t *testing.T) {
		uid := activeAES(t, alice, 128)
		enc, err := alice.Encrypt(uid).Data([]byte("archived")).Exec()
		require.NoError(t, err)

		_, err = alice.Revoke(uid).WithRevocationReasonCode(kmip.RevocationReasonCodeSuperseded).Exec()
		require.NoError(t, err)

		_, err = alice.Encrypt(uid).Data([]byte("new")).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)

		dec, err := alice.Decrypt(uid).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
		require.NoError(t, err)
		require.Equal(t, []byte("archived"), dec.Data)
	})

	t.Run("the usage mask is enforced", func(t *testing.T) {
		created, err := alice.Create().AES(256, kmip.CryptographicUsageEncrypt).Exec()
		require.NoError(t, err)
		_, err = alice.Activate(created.UniqueIdentifier).Exec()
		require.NoError(t, err)

		enc, err := alice.Encrypt(created.UniqueIdentifier).Data([]byte("one way")).Exec()
		require.NoError(t, err)
		_, err = alice.Decrypt(created.UniqueIdentifier).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
		requireReason(t, err, kmip.ResultReasonIllegalOperation)
	})

	t.Run("create, activate and encrypt in one batch", func(t *testing.T) {
		items, err := alice.Batch(context.Background(),
			&payloads.CreateRequestPayload{
				ObjectType: kmip.ObjectTypeSymmetricKey,
				TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{
					{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
					{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
					{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: aesUsage},
				}},
			},
			&payloads.ActivateRequestPayload{},
			&payloads.EncryptRequestPayload{Data: []byte("batched")},
		)
		require.NoError(t, err)
		for _, item := range items {
			require.NoError(t, item.Err())
		}
		enc := items[2].ResponsePayload.(*payloads.EncryptResponsePayload)
		require.Equal(t, items[0].ResponsePayload.(*payloads.CreateResponsePayload).UniqueIdentifier, enc.UniqueIdentifier)
		require.NotEmpty(t, enc.Data)
	})
}

func TestCrypto_OwnershipOverKMIP(t *testing.T) {
	env := newObjectEnv(t)
	alice := env.client(t, "alice")
	bob := env.client(t, "bob")
	uid := activeAES(t, alice, 256)

	enc, err := alice.Encrypt(uid).Data([]byte("alice's secret")).Exec()
	require.NoError(t, err)

	_, err = bob.Encrypt(uid).Data([]byte("x")).Exec()
	requireReason(t, err, kmip.ResultReasonItemNotFound)
	_, err = bob.Decrypt(uid).WithIvCounterNonce(enc.IVCounterNonce).WithAuthTag(enc.AuthenticatedEncryptionTag).Data(enc.Data).Exec()
	requireReason(t, err, kmip.ResultReasonItemNotFound)
}
