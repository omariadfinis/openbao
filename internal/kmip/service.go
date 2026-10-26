package kmip

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/openbao/openbao/v2/internal/kmip/kmipconfig"
)

// tlsConfig builds the listener's TLS configuration.
func tlsConfig(c *kmipconfig.Config) (*tls.Config, error) {
	cfg, err := TLSConfig(c.TLSCertFile, c.TLSKeyFile, c.TLSClientCAFile)
	if err != nil {
		return nil, err
	}
	if !c.TLSRequireClientCert {
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

// Service is a running KMIP listener.
type Service struct {
	*Server
	logger hclog.Logger
}

// Start validates the configuration and starts serving KMIP, running
// operations against core. Use Close to stop it.
func Start(c *kmipconfig.Config, core Requester, logger hclog.Logger) (*Service, error) {
	if err := c.SetDefaultsAndValidate(); err != nil {
		return nil, err
	}
	for _, f := range []string{c.TLSCertFile, c.TLSKeyFile, c.TLSClientCAFile} {
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("kmip: %w", err)
		}
	}

	tlsCfg, err := tlsConfig(c)
	if err != nil {
		return nil, fmt.Errorf("kmip: %w", err)
	}

	auth := &Authenticator{
		Core:      core,
		LoginPath: c.AuthPath,
		Role:      c.AuthRole,
		Namespace: c.AuthNamespace,
	}
	h := NewHandler()
	if c.LogMessages {
		logger.Warn("kmip message logging is on: key material will appear in the log")
		// Registered first so that it also sees requests the authentication
		// middleware refuses.
		h.Use(kmipserver.DebugMiddleware(logger.StandardWriter(&hclog.StandardLoggerOptions{}), ttlv.MarshalXML))
	}
	h.Use(AuthMiddleware(auth))
	h.RegisterObjectOperations(auth, c.MountPath)

	srv, err := NewServer(c.Address, tlsCfg, h)
	if err != nil {
		return nil, fmt.Errorf("kmip: %w", err)
	}

	svc := &Service{Server: srv, logger: logger}
	go func() {
		if err := srv.Serve(); err != nil && !isShutdown(err) {
			logger.Error("kmip listener exited", "error", err)
		}
	}()
	logger.Info("kmip listener started", "address", srv.Addr(), "mount", c.MountPath, "auth", c.AuthPath)
	return svc, nil
}

// Close stops the listener and waits for running requests.
func (s *Service) Close() error {
	return s.Shutdown()
}
