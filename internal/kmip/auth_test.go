package kmip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/sdk/v2/logical"
	certauth "github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	"github.com/openbao/openbao/v2/internal/builtin/logical/transit"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault"
)

const rolePolicy = `path "transit/keys/*" { capabilities = ["create", "read", "update"] }`

// newCore returns an unsealed core with the cert auth method and transit
// mounted, and a cert auth role that trusts the CA and accepts only the
// common name "kmip-client".
func newCore(t *testing.T, pki *testPKI) (*vault.Core, string) {
	t.Helper()

	core, _, root := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{"cert": certauth.Factory},
		LogicalBackends:    map[string]logical.Factory{"transit": transit.Factory},
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
	write("sys/mounts/transit", map[string]any{"type": "transit"})
	write("sys/policies/acl/kmip", map[string]any{"policy": rolePolicy})
	write("auth/cert/certs/kmip-client", map[string]any{
		"certificate":          string(pki.caPEM),
		"allowed_common_names": "kmip-client",
		"token_policies":       "kmip",
	})

	return core, root
}

// newAuthServer starts a KMIP server that authenticates clients against the
// core. Clients may connect without a certificate so that unauthenticated
// Query can be exercised; every other operation requires one.
//
// Activate is used as a stand-in operation. By default it creates the transit
// key named by the unique identifier, as the authenticated identity; an
// identifier of the form "read:<path>" reads that path instead, so tests can
// probe what the identity's policy allows.
func newAuthServer(t *testing.T, core *vault.Core, pki *testPKI) (addr string, auth *Authenticator) {
	t.Helper()

	dir := t.TempDir()
	srvCert, srvKey := pki.issue(t, "kmip server", x509.ExtKeyUsageServerAuth)
	cfg, err := TLSConfig(
		writeFile(t, dir, "server.pem", srvCert),
		writeFile(t, dir, "server.key", srvKey),
		writeFile(t, dir, "ca.pem", pki.caPEM),
	)
	require.NoError(t, err)
	cfg.ClientAuth = tls.VerifyClientCertIfGiven

	auth = &Authenticator{Core: core, LoginPath: "auth/cert/login", Role: "kmip-client"}

	h := NewHandler()
	h.Use(AuthMiddleware(auth))
	h.Handle(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		if IdentityFromContext(ctx) == nil {
			return nil, errors.New("handler ran without an identity")
		}
		op, path := logical.UpdateOperation, "transit/keys/"+req.UniqueIdentifier
		if p, ok := strings.CutPrefix(req.UniqueIdentifier, "read:"); ok {
			op, path = logical.ReadOperation, p
		}
		if _, err := auth.Do(ctx, op, path, nil); err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "%v", err)
		}
		return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	srv, err := NewServer("127.0.0.1:0", cfg, h)
	require.NoError(t, err)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return srv.Addr(), auth
}

func dial(t *testing.T, addr string, pki *testPKI, cn string) *kmipclient.Client {
	t.Helper()
	opts := []kmipclient.Option{kmipclient.WithRootCAPem(pki.caPEM)}
	if cn != "" {
		certPEM, keyPEM := pki.issue(t, cn, x509.ExtKeyUsageClientAuth)
		opts = append(opts, kmipclient.WithClientCertPEM(certPEM, keyPEM))
	}
	client, err := kmipclient.Dial(addr, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestCertAuth_EndToEnd(t *testing.T) {
	pki := newTestPKI(t)
	core, root := newCore(t, pki)
	addr, _ := newAuthServer(t, core, pki)

	t.Run("query needs no certificate", func(t *testing.T) {
		client := dial(t, addr, pki, "")
		resp, err := client.Query().ServerInformation().Exec()
		require.NoError(t, err)
		require.Equal(t, VendorIdentification, resp.VendorIdentification)
	})

	t.Run("other operations need a certificate", func(t *testing.T) {
		client := dial(t, addr, pki, "")
		resp, err := client.Activate("anonymous-key").Exec()
		require.Nil(t, resp)
		require.ErrorContains(t, err, ttlv.EnumStr(kmip.ResultReasonPermissionDenied))
	})

	t.Run("certificate rejected by the role", func(t *testing.T) {
		// Trusted CA, but the common name is not allowed by the role.
		client := dial(t, addr, pki, "someone-else")
		resp, err := client.Activate("intruder-key").Exec()
		require.Nil(t, resp)
		require.ErrorContains(t, err, ttlv.EnumStr(kmip.ResultReasonPermissionDenied))
	})

	t.Run("accepted certificate acts as its identity", func(t *testing.T) {
		client := dial(t, addr, pki, "kmip-client")
		resp, err := client.Activate("tenant-key").Exec()
		require.NoError(t, err)
		require.Equal(t, "tenant-key", resp.UniqueIdentifier)

		// The key was created by the cert-authenticated identity, using the
		// role's policy.
		req := logical.TestRequest(t, logical.ReadOperation, "transit/keys/tenant-key")
		req.ClientToken = root
		got, err := core.HandleRequest(namespace.RootContext(t.Context()), req)
		require.NoError(t, err)
		require.Equal(t, "tenant-key", got.Data["name"])
	})

	t.Run("denied outside the role's policy", func(t *testing.T) {
		client := dial(t, addr, pki, "kmip-client")

		// Authenticated, but the policy grants nothing on sys/mounts.
		resp, err := client.Activate("read:sys/mounts").Exec()
		require.Nil(t, resp)
		require.ErrorContains(t, err, "permission denied")
		require.NotContains(t, err.Error(), ErrUnauthenticated.Error())

		// The same identity can still read a key under the permitted prefix.
		_, err = client.Activate("read:transit/keys/tenant-key").Exec()
		require.NoError(t, err)
	})
}

func TestAuthenticate_Identity(t *testing.T) {
	pki := newTestPKI(t)
	core, _ := newCore(t, pki)

	var got *Identity
	var gotErr error
	auth := &Authenticator{Core: core, LoginPath: "auth/cert/login", Role: "kmip-client"}

	dir := t.TempDir()
	srvCert, srvKey := pki.issue(t, "kmip server", x509.ExtKeyUsageServerAuth)
	cfg, err := TLSConfig(
		writeFile(t, dir, "server.pem", srvCert),
		writeFile(t, dir, "server.key", srvKey),
		writeFile(t, dir, "ca.pem", pki.caPEM),
	)
	require.NoError(t, err)

	h := NewHandler()
	h.Handle(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		got, gotErr = auth.Authenticate(ctx)
		return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))
	srv, err := NewServer("127.0.0.1:0", cfg, h)
	require.NoError(t, err)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	client := dial(t, srv.Addr(), pki, "kmip-client")
	_, err = client.Activate("x").Exec()
	require.NoError(t, err)

	require.NoError(t, gotErr)
	require.NotNil(t, got)
	require.Contains(t, got.Policies, "kmip")
	require.NotEmpty(t, got.DisplayName)
}
