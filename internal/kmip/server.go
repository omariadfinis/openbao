package kmip

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ovh/kmip-go/kmipserver"
)

// TLSConfig builds a server TLS configuration that requires and verifies a
// client certificate against the CA bundle in clientCAFile (mTLS).
func TLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}

	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading client CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates found in client CA file")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Server is a KMIP server bound to a listener.
type Server struct {
	*kmipserver.Server
	ln net.Listener
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// NewServer wraps a TLS listener on addr with a KMIP server using h.
func NewServer(addr string, cfg *tls.Config, h *Handler) (*Server, error) {
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}
	return NewServerFromListener(ln, h), nil
}

// NewServerFromListener serves KMIP on an existing listener.
func NewServerFromListener(ln net.Listener, h *Handler) *Server {
	return &Server{Server: kmipserver.NewServer(ln, h), ln: ln}
}

func isShutdown(err error) bool {
	return errors.Is(err, kmipserver.ErrShutdown)
}
