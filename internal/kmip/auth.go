package kmip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/ovh/kmip-go/kmipserver"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ErrUnauthenticated is returned when a KMIP connection presented no client
// certificate, or the certificate was rejected by the auth method.
var ErrUnauthenticated = errors.New("kmip: client certificate authentication failed")

// Requester executes logical requests. *vault.Core satisfies it.
type Requester interface {
	HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error)
}

// Identity is the OpenBao identity a KMIP connection authenticated as.
type Identity struct {
	EntityID    string
	DisplayName string
	Policies    []string
	Metadata    map[string]string
}

// Authenticator maps a KMIP client's TLS certificate to an OpenBao identity.
//
// KMIP has no bearer token: clients are identified by the certificate they
// present during the TLS handshake. The Authenticator uses OpenBao's inline
// authentication, which performs a login against the configured auth method
// (typically the cert auth method) as part of each request and does not
// persist a token. Because every request carries its own login, there is no
// token to cache, renew or revoke, and a certificate that stops matching its
// role stops working immediately.
type Authenticator struct {
	// Core executes the requests.
	Core Requester

	// LoginPath is the login path of the auth method, e.g. "auth/cert/login".
	LoginPath string

	// Role is the optional cert auth role to log in against. When empty the
	// auth method tries every role.
	Role string

	// Namespace is the optional namespace the auth method is mounted in.
	Namespace string
}

// NewRequest builds a request that runs as the identity of the certificate on
// the KMIP connection in ctx. Executing it performs the inline login first.
func (a *Authenticator) NewRequest(ctx context.Context, op logical.Operation, path string, data map[string]any) (*logical.Request, error) {
	conn, err := connectionFromContext(ctx)
	if err != nil {
		return nil, err
	}

	headers := map[string][]string{
		consts.InlineAuthPathHeaderName: {a.LoginPath},
	}
	if a.Namespace != "" {
		headers[consts.InlineAuthNamespaceHeaderName] = []string{a.Namespace}
	}
	if a.Role != "" {
		key := consts.InlineAuthParameterHeaderPrefix + "name"
		raw, err := json.Marshal(map[string]any{"key": "name", "value": a.Role})
		if err != nil {
			return nil, fmt.Errorf("encoding inline auth role: %w", err)
		}
		headers[key] = []string{base64.RawURLEncoding.EncodeToString(raw)}
	}

	return &logical.Request{
		Operation:  op,
		Path:       path,
		Data:       data,
		Connection: conn,
		Headers:    headers,
	}, nil
}

// Do executes a logical request as the connection's certificate identity.
func (a *Authenticator) Do(ctx context.Context, op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
	req, err := a.NewRequest(ctx, op, path, data)
	if err != nil {
		return nil, err
	}

	resp, err := a.Core.HandleRequest(ctx, req)
	if !req.HasInlineAuth {
		// The login step failed, so nothing past it ran.
		if err != nil {
			return resp, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
		}
		return resp, ErrUnauthenticated
	}

	return resp, err
}

// Authenticate verifies the connection's certificate and returns the
// identity it maps to. It issues a read of the caller's own token, which any
// policy set with the default policy may do; the result of that read is
// irrelevant, only whether the inline login succeeded.
func (a *Authenticator) Authenticate(ctx context.Context) (*Identity, error) {
	req, err := a.NewRequest(ctx, logical.ReadOperation, "auth/token/lookup-self", nil)
	if err != nil {
		return nil, err
	}

	_, err = a.Core.HandleRequest(ctx, req)
	if !req.HasInlineAuth || req.InlineAuth == nil {
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
		}
		return nil, ErrUnauthenticated
	}

	auth := req.InlineAuth
	return &Identity{
		EntityID:    auth.EntityID,
		DisplayName: auth.DisplayName,
		Policies:    auth.Policies,
		Metadata:    auth.Metadata,
	}, nil
}

// connectionFromContext converts the KMIP connection state into the
// connection information cert auth reads.
func connectionFromContext(ctx context.Context) (*logical.Connection, error) {
	state := kmipserver.TLSConnectionState(ctx)
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%w: no client certificate presented", ErrUnauthenticated)
	}

	conn := &logical.Connection{
		ConnState:        state,
		PeerCertificates: state.PeerCertificates,
	}

	host, port, err := net.SplitHostPort(kmipserver.RemoteAddr(ctx))
	if err == nil {
		conn.RemoteAddr = host
		conn.RemotePort, _ = strconv.Atoi(port)
	}

	return conn, nil
}
