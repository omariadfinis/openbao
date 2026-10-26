package kmip

import (
	"context"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

type identityKey struct{}

// IdentityFromContext returns the identity the authentication middleware
// resolved for the current request, or nil for an unauthenticated request.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}

// unauthenticatedOperations may be invoked without a client certificate: the
// specification expects servers to let clients discover versions and query
// capabilities before authenticating.
var unauthenticatedOperations = map[kmip.Operation]bool{
	kmip.OperationDiscoverVersions: true,
	kmip.OperationQuery:            true,
}

// AuthMiddleware authenticates every message that contains an operation other
// than Discover Versions or Query, and makes the resulting identity available
// to handlers through IdentityFromContext. A failed authentication is
// answered with Permission Denied and no operation is run.
func AuthMiddleware(a *Authenticator) kmipserver.Middleware {
	return func(next kmipserver.Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		if !needsAuthentication(msg) {
			return next(ctx, msg)
		}

		id, err := a.Authenticate(ctx)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "client certificate not accepted")
		}

		return next(context.WithValue(ctx, identityKey{}, id), msg)
	}
}

func needsAuthentication(msg *kmip.RequestMessage) bool {
	for _, bi := range msg.BatchItem {
		if !unauthenticatedOperations[bi.Operation] {
			return true
		}
	}
	return false
}
