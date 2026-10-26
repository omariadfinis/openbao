package kmip

import (
	"crypto/x509"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/v2/internal/kmip/kmipconfig"
)

func TestConfigStart(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	srvCert, srvKey := pki.issue(t, "kmip server", x509.ExtKeyUsageServerAuth)

	cfg := &kmipconfig.Config{
		Address:              "127.0.0.1:0",
		TLSCertFile:          writeFile(t, dir, "server.pem", srvCert),
		TLSKeyFile:           writeFile(t, dir, "server.key", srvKey),
		TLSClientCAFile:      writeFile(t, dir, "ca.pem", pki.caPEM),
		TLSRequireClientCert: true,
	}

	svc, err := Start(cfg, nil, hclog.NewNullLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	certPEM, keyPEM := pki.issue(t, "client", x509.ExtKeyUsageClientAuth)
	c, err := kmipclient.Dial(svc.Addr(), kmipclient.WithRootCAPem(pki.caPEM), kmipclient.WithClientCertPEM(certPEM, keyPEM))
	require.NoError(t, err)
	defer c.Close()
	require.Equal(t, kmip.V1_4, c.Version())

	resp, err := c.Query().Operations().ServerInformation().Exec()
	require.NoError(t, err)
	require.Equal(t, VendorIdentification, resp.VendorIdentification)
	require.Contains(t, resp.Operations, kmip.OperationRegister, "object operations are registered by Start")

	t.Run("missing files are reported", func(t *testing.T) {
		bad := *cfg
		bad.TLSCertFile = dir + "/missing.pem"
		_, err := Start(&bad, nil, hclog.NewNullLogger())
		require.Error(t, err)
	})
}

func TestConfigStart_OptionalClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	srvCert, srvKey := pki.issue(t, "kmip server", x509.ExtKeyUsageServerAuth)

	cfg := &kmipconfig.Config{
		Address:              "127.0.0.1:0",
		TLSCertFile:          writeFile(t, dir, "server.pem", srvCert),
		TLSKeyFile:           writeFile(t, dir, "server.key", srvKey),
		TLSClientCAFile:      writeFile(t, dir, "ca.pem", pki.caPEM),
		TLSRequireClientCert: false,
	}
	svc, err := Start(cfg, nil, hclog.NewNullLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	// No client certificate: Query works, anything else is refused before it
	// reaches the core (which is nil here and would panic if reached).
	c, err := kmipclient.Dial(svc.Addr(), kmipclient.WithRootCAPem(pki.caPEM))
	require.NoError(t, err)
	defer c.Close()

	_, err = c.Query().ServerInformation().Exec()
	require.NoError(t, err)
	_, err = c.Create().AES(256, aesUsage).Exec()
	requireReason(t, err, kmip.ResultReasonPermissionDenied)
}
