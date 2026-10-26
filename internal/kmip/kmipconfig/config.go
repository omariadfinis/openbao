// Package kmipconfig holds the "kmip" block of the server configuration. It is
// separate from the KMIP implementation so that the server configuration
// package can depend on it without importing the whole protocol stack.
package kmipconfig

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// Config is the "kmip" block of the server configuration:
//
//	kmip {
//	  address            = "0.0.0.0:5696"
//	  tls_cert_file      = "/path/to/server.pem"
//	  tls_key_file       = "/path/to/server.key"
//	  tls_client_ca_file = "/path/to/clients-ca.pem"
//	  auth_path          = "auth/cert/login"
//	  auth_role          = "kmip-clients"
//	  mount_path         = "kmip/"
//	}
//
// Clients authenticate with their TLS certificate, which is logged in against
// the cert auth method mounted at auth_path. Every operation then runs as the
// identity that login yields, so policies, audit and namespaces apply.
type Config struct {
	// Address is the host and port to listen on. The KMIP default port is
	// 5696.
	Address string `hcl:"address"`

	TLSCertFile string `hcl:"tls_cert_file"`
	TLSKeyFile  string `hcl:"tls_key_file"`

	// TLSClientCAFile holds the CAs that issue client certificates.
	TLSClientCAFile string `hcl:"tls_client_ca_file"`

	// TLSRequireClientCert makes the listener refuse connections without a
	// client certificate. It defaults to true. When false, a client without a
	// certificate may still call Query and Discover Versions, as the
	// specification suggests, but nothing else.
	TLSRequireClientCert    bool `hcl:"-"`
	TLSRequireClientCertRaw any  `hcl:"tls_require_client_cert"`

	// AuthPath is the login path of the cert auth method. It defaults to
	// auth/cert/login.
	AuthPath string `hcl:"auth_path"`

	// AuthRole optionally names the cert auth role to log in against.
	AuthRole string `hcl:"auth_role"`

	// AuthNamespace is the namespace of the auth method, if not the root.
	AuthNamespace string `hcl:"auth_namespace"`

	// LogMessages logs every KMIP request and response, as XML, to the
	// server log. It is for debugging a client's behaviour and writes
	// sensitive values (key material), so never enable it in production.
	LogMessages    bool `hcl:"-"`
	LogMessagesRaw any  `hcl:"log_messages"`

	// MountPath is where the kmip secrets engine is mounted. It defaults to
	// kmip/.
	MountPath string `hcl:"mount_path"`
}

const (
	defaultAddress   = "127.0.0.1:5696"
	defaultAuthPath  = "auth/cert/login"
	defaultMountPath = "kmip/"
)

// ParseConfig reads the kmip block from a parsed configuration. It returns
// nil when there is none.
func ParseConfig(list *ast.ObjectList) (*Config, error) {
	blocks := list.Filter("kmip")
	switch len(blocks.Items) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, errors.New("only one kmip block may be configured")
	}

	cfg := &Config{TLSRequireClientCert: true}
	if err := hcl.DecodeObject(cfg, blocks.Items[0].Val); err != nil {
		return nil, fmt.Errorf("parsing kmip block: %w", err)
	}

	if cfg.TLSRequireClientCertRaw != nil {
		switch v := strings.ToLower(fmt.Sprint(cfg.TLSRequireClientCertRaw)); v {
		case "true", "1":
			cfg.TLSRequireClientCert = true
		case "false", "0":
			cfg.TLSRequireClientCert = false
		default:
			return nil, fmt.Errorf("kmip: invalid tls_require_client_cert %q", v)
		}
	}

	if cfg.LogMessagesRaw != nil {
		switch v := strings.ToLower(fmt.Sprint(cfg.LogMessagesRaw)); v {
		case "true", "1":
			cfg.LogMessages = true
		case "false", "0":
		default:
			return nil, fmt.Errorf("kmip: invalid log_messages %q", v)
		}
	}

	if err := cfg.SetDefaultsAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SetDefaultsAndValidate fills in defaults and checks required settings.
func (c *Config) SetDefaultsAndValidate() error {
	if c.Address == "" {
		c.Address = defaultAddress
	}
	if c.AuthPath == "" {
		c.AuthPath = defaultAuthPath
	}
	if c.MountPath == "" {
		c.MountPath = defaultMountPath
	}
	if !strings.HasSuffix(c.MountPath, "/") {
		c.MountPath += "/"
	}

	switch {
	case c.TLSCertFile == "" || c.TLSKeyFile == "":
		return errors.New("kmip: tls_cert_file and tls_key_file are required")
	case c.TLSClientCAFile == "":
		return errors.New("kmip: tls_client_ca_file is required: clients are identified by their certificate")
	}
	return nil
}
