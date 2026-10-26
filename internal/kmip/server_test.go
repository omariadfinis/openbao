package kmip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/stretchr/testify/require"
)

type testPKI struct {
	caPEM []byte
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kmip test ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testPKI{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		ca:    ca,
		caKey: key,
	}
}

// issue returns PEM-encoded certificate and key signed by the test CA.
func (p *testPKI) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, key.Public(), p.caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestMutualTLS_ClientCertRequired(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()

	srvCert, srvKey := pki.issue(t, "kmip server", x509.ExtKeyUsageServerAuth)
	cfg, err := TLSConfig(
		writeFile(t, dir, "server.pem", srvCert),
		writeFile(t, dir, "server.key", srvKey),
		writeFile(t, dir, "ca.pem", pki.caPEM),
	)
	require.NoError(t, err)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	srv := NewServerFromListener(ln, NewHandler())
	go func() {
		if err := srv.Serve(); err != nil && !errors.Is(err, kmipserver.ErrShutdown) {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr := ln.Addr().String()

	// A rejected client certificate surfaces as a TLS alert, which with TLS
	// 1.3 arrives on the first read rather than during the handshake. These
	// cases use a plain TLS client so they test only the listener.
	rejected := func(t *testing.T, cert *tls.Certificate) {
		t.Helper()
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM(pki.caPEM))
		cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}

		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			return // refused during the handshake
		}
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = conn.Read(make([]byte, 1))
		require.Error(t, err)
		require.NotErrorIs(t, err, os.ErrDeadlineExceeded)
	}

	t.Run("no client certificate is rejected", func(t *testing.T) {
		rejected(t, nil)
	})

	t.Run("certificate from another CA is rejected", func(t *testing.T) {
		other := newTestPKI(t)
		certPEM, keyPEM := other.issue(t, "intruder", x509.ExtKeyUsageClientAuth)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		rejected(t, &cert)
	})

	t.Run("certificate from the trusted CA is accepted", func(t *testing.T) {
		certPEM, keyPEM := pki.issue(t, "kmip client", x509.ExtKeyUsageClientAuth)
		client, err := kmipclient.Dial(addr,
			kmipclient.WithRootCAPem(pki.caPEM),
			kmipclient.WithClientCertPEM(certPEM, keyPEM),
		)
		require.NoError(t, err)
		defer client.Close()

		resp, err := client.Query().ServerInformation().Exec()
		require.NoError(t, err)
		require.Equal(t, VendorIdentification, resp.VendorIdentification)
	})
}
