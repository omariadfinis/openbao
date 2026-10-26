package kmipconfig

import (
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/stretchr/testify/require"
)

func parse(t *testing.T, src string) (*Config, error) {
	t.Helper()
	root, err := hcl.Parse(src)
	require.NoError(t, err)
	return ParseConfig(root.Node.(*ast.ObjectList))
}

func TestParseConfig(t *testing.T) {
	t.Run("no block", func(t *testing.T) {
		cfg, err := parse(t, `ui = true`)
		require.NoError(t, err)
		require.Nil(t, cfg)
	})

	t.Run("defaults", func(t *testing.T) {
		cfg, err := parse(t, `
kmip {
  tls_cert_file      = "server.pem"
  tls_key_file       = "server.key"
  tls_client_ca_file = "ca.pem"
}`)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:5696", cfg.Address)
		require.Equal(t, "auth/cert/login", cfg.AuthPath)
		require.Equal(t, "kmip/", cfg.MountPath)
		require.True(t, cfg.TLSRequireClientCert)
		require.Empty(t, cfg.AuthRole)
	})

	t.Run("every option", func(t *testing.T) {
		cfg, err := parse(t, `
kmip {
  address                = "0.0.0.0:5697"
  tls_cert_file          = "server.pem"
  tls_key_file           = "server.key"
  tls_client_ca_file     = "ca.pem"
  tls_require_client_cert = false
  auth_path              = "auth/kmip-certs/login"
  auth_role              = "clients"
  auth_namespace         = "team-a"
  mount_path             = "keys"
}`)
		require.NoError(t, err)
		require.Equal(t, "0.0.0.0:5697", cfg.Address)
		require.False(t, cfg.TLSRequireClientCert)
		require.Equal(t, "auth/kmip-certs/login", cfg.AuthPath)
		require.Equal(t, "clients", cfg.AuthRole)
		require.Equal(t, "team-a", cfg.AuthNamespace)
		require.Equal(t, "keys/", cfg.MountPath, "a trailing slash is added")
	})

	t.Run("required settings", func(t *testing.T) {
		_, err := parse(t, `kmip { tls_cert_file = "a" }`)
		require.ErrorContains(t, err, "tls_cert_file and tls_key_file")

		_, err = parse(t, `kmip { tls_cert_file = "a"
 tls_key_file = "b" }`)
		require.ErrorContains(t, err, "tls_client_ca_file")
	})

	t.Run("one block only", func(t *testing.T) {
		_, err := parse(t, `
kmip { tls_cert_file = "a"
 tls_key_file = "b"
 tls_client_ca_file = "c" }
kmip { tls_cert_file = "a"
 tls_key_file = "b"
 tls_client_ca_file = "c" }`)
		require.ErrorContains(t, err, "only one kmip block")
	})
}
