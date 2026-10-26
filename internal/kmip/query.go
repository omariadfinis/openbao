package kmip

import (
	"context"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// handleQuery answers the Query operation. Functions the server does not
// implement are ignored, which yields an empty section in the response as the
// specification allows.
func (h *Handler) handleQuery(_ context.Context, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	resp := &payloads.QueryResponsePayload{}

	for _, fn := range req.QueryFunction {
		switch fn {
		case kmip.QueryFunctionOperations:
			resp.Operations = h.Operations()
		case kmip.QueryFunctionObjects:
			resp.ObjectType = h.ObjectTypes()
		case kmip.QueryFunctionServerInformation:
			resp.VendorIdentification = VendorIdentification
		}
	}

	return resp, nil
}
