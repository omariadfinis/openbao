package kmip

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openbao/openbao/sdk/v2/logical"
	engine "github.com/openbao/openbao/v2/internal/builtin/logical/kmip"
)

// objectOps executes KMIP object operations against the kmip secrets engine
// mounted at mount, as the identity of the connection's client certificate.
type objectOps struct {
	auth  *Authenticator
	mount string
}

// RegisterObjectOperations serves the object lifecycle, attribute and
// cryptographic operations from the kmip secrets engine mounted at mount.
func (h *Handler) RegisterObjectOperations(auth *Authenticator, mount string) {
	o := &objectOps{auth: auth, mount: mount}

	for _, t := range []kmip.ObjectType{
		kmip.ObjectTypeSymmetricKey, kmip.ObjectTypeSecretData, kmip.ObjectTypeOpaqueObject,
		kmip.ObjectTypePrivateKey, kmip.ObjectTypePublicKey,
	} {
		h.AddObjectType(t)
	}

	// Object lifecycle.
	h.Handle(kmip.OperationCreate, kmipserver.HandleFunc(o.create))
	h.Handle(kmip.OperationRegister, kmipserver.HandleFunc(o.register))
	h.Handle(kmip.OperationCreateKeyPair, kmipserver.HandleFunc(o.createKeyPair))
	h.Handle(kmip.OperationReKey, kmipserver.HandleFunc(o.rekey))
	h.Handle(kmip.OperationReKeyKeyPair, kmipserver.HandleFunc(o.rekeyKeyPair))
	h.Handle(kmip.OperationGet, kmipserver.HandleFunc(o.get))
	h.Handle(kmip.OperationLocate, kmipserver.HandleFunc(o.locate))
	h.Handle(kmip.OperationCheck, kmipserver.HandleFunc(o.check))
	h.Handle(kmip.OperationActivate, kmipserver.HandleFunc(o.activate))
	h.Handle(kmip.OperationRevoke, kmipserver.HandleFunc(o.revoke))
	h.Handle(kmip.OperationDestroy, kmipserver.HandleFunc(o.destroy))

	// Attributes.
	h.Handle(kmip.OperationGetAttributes, kmipserver.HandleFunc(o.getAttributes))
	h.Handle(kmip.OperationGetAttributeList, kmipserver.HandleFunc(o.getAttributeList))
	h.Handle(kmip.OperationAddAttribute, kmipserver.HandleFunc(o.addAttribute))
	h.Handle(kmip.OperationModifyAttribute, kmipserver.HandleFunc(o.modifyAttribute))
	h.Handle(kmip.OperationDeleteAttribute, kmipserver.HandleFunc(o.deleteAttribute))

	// Cryptographic operations.
	h.Handle(kmip.OperationEncrypt, kmipserver.HandleFunc(o.encrypt))
	h.Handle(kmip.OperationDecrypt, kmipserver.HandleFunc(o.decrypt))
	h.Handle(kmip.OperationSign, kmipserver.HandleFunc(o.sign))
	h.Handle(kmip.OperationSignatureVerify, kmipserver.HandleFunc(o.signatureVerify))
	h.Handle(kmip.OperationMAC, kmipserver.HandleFunc(o.mac))
	h.Handle(kmip.OperationMACVerify, kmipserver.HandleFunc(o.macVerify))
	h.Handle(kmip.OperationHash, kmipserver.HandleFunc(o.hash))
	h.Handle(kmip.OperationRNGRetrieve, kmipserver.HandleFunc(o.rngRetrieve))
}

var engineReasons = map[string]kmip.ResultReason{
	engine.ReasonPermissionDenied:     kmip.ResultReasonPermissionDenied,
	engine.ReasonItemNotFound:         kmip.ResultReasonItemNotFound,
	engine.ReasonInvalidField:         kmip.ResultReasonInvalidField,
	engine.ReasonIllegalOperation:     kmip.ResultReasonIllegalOperation,
	engine.ReasonFeatureNotSupported:  kmip.ResultReasonFeatureNotSupported,
	engine.ReasonKeyValueNotPresent:   kmip.ResultReasonKeyValueNotPresent,
	engine.ReasonNotExtractable:       kmip.ResultReasonNotExtractable,
	engine.ReasonSensitive:            kmip.ResultReasonSensitive,
	engine.ReasonMissingData:          kmip.ResultReasonMissingData,
	engine.ReasonCryptographicFailure: kmip.ResultReasonCryptographicFailure,
}

// call runs a request against the engine and turns every failure into a KMIP
// error.
func (o *objectOps) call(ctx context.Context, op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
	resp, err := o.auth.Do(ctx, op, o.mount+path, data)
	switch {
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, logical.ErrPermissionDenied):
		return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "permission denied")
	case err != nil:
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	case resp == nil:
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "empty response")
	case resp.IsError():
		reason := kmip.ResultReasonInvalidField
		if mapped, ok := engineReasons[engine.Reason(resp)]; ok {
			reason = mapped
		}
		return nil, kmipserver.Errorf(reason, "%s", resp.Error())
	}
	return resp, nil
}

// target resolves the unique identifier of a request, which may be omitted
// in favour of the batch's ID placeholder.
func target(ctx context.Context, id string) (string, error) {
	return kmipserver.GetIdOrPlaceholder(ctx, id)
}

// readAttributes fetches the engine's attributes for an object.
func (o *objectOps) readAttributes(ctx context.Context, uid string) (map[string][]string, error) {
	resp, err := o.call(ctx, logical.ReadOperation, "attributes/"+uid, nil)
	if err != nil {
		return nil, err
	}

	raw, _ := resp.Data["attributes"].(map[string]any)
	attrs := make(map[string][]string, len(raw))
	for name, v := range raw {
		values, ok := v.([]string)
		if !ok {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "unexpected value for attribute %q: %T", name, v)
		}
		attrs[name] = values
	}
	return attrs, nil
}

func (o *objectOps) getAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	attrs, err := o.readAttributes(ctx, uid)
	if err != nil {
		return nil, err
	}
	out, err := attributesFromEngine(attrs, req.AttributeName)
	if err != nil {
		return nil, err
	}
	return &payloads.GetAttributesResponsePayload{UniqueIdentifier: uid, Attribute: out}, nil
}

func (o *objectOps) getAttributeList(ctx context.Context, req *payloads.GetAttributeListRequestPayload) (*payloads.GetAttributeListResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	attrs, err := o.readAttributes(ctx, uid)
	if err != nil {
		return nil, err
	}

	resp := &payloads.GetAttributeListResponsePayload{UniqueIdentifier: uid}
	for name := range attrs {
		resp.AttributeName = append(resp.AttributeName, kmip.AttributeName(name))
	}
	slices.Sort(resp.AttributeName)
	return resp, nil
}

// mutateAttribute adds, modifies or deletes one attribute instance and
// returns the instance as KMIP represents it.
func (o *objectOps) mutateAttribute(ctx context.Context, action, id string, attr kmip.Attribute) (string, kmip.Attribute, error) {
	uid, err := target(ctx, id)
	if err != nil {
		return "", kmip.Attribute{}, err
	}

	data := map[string]any{"action": action, "name": string(attr.AttributeName)}
	if attr.AttributeIndex != nil {
		data["index"] = int(*attr.AttributeIndex)
	}
	if action != "delete" {
		value, err := attributeValueString(attr.AttributeName, attr.AttributeValue)
		if err != nil {
			return "", kmip.Attribute{}, err
		}
		data["value"] = value
	}

	// A deleted attribute is returned as it was before deletion.
	var before []kmip.Attribute
	if action == "delete" {
		attrs, err := o.readAttributes(ctx, uid)
		if err != nil {
			return "", kmip.Attribute{}, err
		}
		before, _ = attributeFromStrings(attr.AttributeName, attrs[string(attr.AttributeName)])
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "attributes/"+uid, data)
	if err != nil {
		return "", kmip.Attribute{}, err
	}

	if action == "delete" {
		idx := 0
		if attr.AttributeIndex != nil {
			idx = int(*attr.AttributeIndex)
		}
		if idx >= len(before) {
			return uid, kmip.Attribute{AttributeName: attr.AttributeName, AttributeIndex: attr.AttributeIndex}, nil
		}
		return uid, before[idx], nil
	}

	values, _ := resp.Data["values"].([]string)
	instances, err := attributeFromStrings(attr.AttributeName, values)
	if err != nil {
		return "", kmip.Attribute{}, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	if len(instances) == 0 {
		return uid, kmip.Attribute{AttributeName: attr.AttributeName}, nil
	}

	// Single-valued attributes have one instance. For a multi-valued one,
	// add appends and modify replaces in place.
	pick := len(instances) - 1
	if action == "modify" && attr.AttributeIndex != nil && int(*attr.AttributeIndex) < len(instances) {
		pick = int(*attr.AttributeIndex)
	}
	return uid, instances[pick], nil
}

func (o *objectOps) addAttribute(ctx context.Context, req *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
	uid, attr, err := o.mutateAttribute(ctx, "add", req.UniqueIdentifier, req.Attribute)
	if err != nil {
		return nil, err
	}
	return &payloads.AddAttributeResponsePayload{UniqueIdentifier: uid, Attribute: attr}, nil
}

func (o *objectOps) modifyAttribute(ctx context.Context, req *payloads.ModifyAttributeRequestPayload) (*payloads.ModifyAttributeResponsePayload, error) {
	uid, attr, err := o.mutateAttribute(ctx, "modify", req.UniqueIdentifier, req.Attribute)
	if err != nil {
		return nil, err
	}
	return &payloads.ModifyAttributeResponsePayload{UniqueIdentifier: uid, Attribute: attr}, nil
}

func (o *objectOps) deleteAttribute(ctx context.Context, req *payloads.DeleteAttributeRequestPayload) (*payloads.DeleteAttributeResponsePayload, error) {
	uid, attr, err := o.mutateAttribute(ctx, "delete", req.UniqueIdentifier, kmip.Attribute{
		AttributeName:  req.AttributeName,
		AttributeIndex: req.AttributeIndex,
	})
	if err != nil {
		return nil, err
	}
	return &payloads.DeleteAttributeResponsePayload{UniqueIdentifier: uid, Attribute: attr}, nil
}

func (o *objectOps) locate(ctx context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	filters := make([]string, 0, len(req.Attribute))
	for _, attr := range req.Attribute {
		value, err := attributeValueString(attr.AttributeName, attr.AttributeValue)
		if err != nil {
			// An object type or algorithm this server does not support can
			// match nothing, so the result is empty rather than an error.
			if attr.AttributeName == kmip.AttributeNameObjectType || attr.AttributeName == kmip.AttributeNameCryptographicAlgorithm {
				zero := int32(0)
				return &payloads.LocateResponsePayload{LocatedItems: &zero}, nil
			}
			return nil, err
		}
		filters = append(filters, fmt.Sprintf("%s=%s", attr.AttributeName, value))
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "locate", map[string]any{
		"filters":   filters,
		"max_items": int(req.MaximumItems),
		"offset":    int(req.OffsetItems),
	})
	if err != nil {
		return nil, err
	}

	uids, _ := resp.Data["uids"].([]string)
	total, _ := resp.Data["located_items"].(int)
	located := int32(total)

	if len(uids) > 0 {
		kmipserver.SetIdPlaceholder(ctx, uids[0])
	}
	return &payloads.LocateResponsePayload{LocatedItems: &located, UniqueIdentifier: uids}, nil
}

func (o *objectOps) activate(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if _, err := o.call(ctx, logical.UpdateOperation, "activate/"+uid, nil); err != nil {
		return nil, err
	}
	return &payloads.ActivateResponsePayload{UniqueIdentifier: uid}, nil
}

func (o *objectOps) revoke(ctx context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}

	code := req.RevocationReason.RevocationReasonCode
	token, ok := reasonTokens[code]
	if !ok {
		return nil, errField("unknown revocation reason code %v", code)
	}

	data := map[string]any{"reason_code": token, "message": req.RevocationReason.RevocationMessage}
	if req.CompromiseOccurrenceDate != nil {
		data["compromise_occurrence_date"] = req.CompromiseOccurrenceDate.UTC().Format(time.RFC3339)
	}

	if _, err := o.call(ctx, logical.UpdateOperation, "revoke/"+uid, data); err != nil {
		return nil, err
	}
	return &payloads.RevokeResponsePayload{UniqueIdentifier: uid}, nil
}

func (o *objectOps) destroy(ctx context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if _, err := o.call(ctx, logical.UpdateOperation, "destroy/"+uid, nil); err != nil {
		return nil, err
	}
	return &payloads.DestroyResponsePayload{UniqueIdentifier: uid}, nil
}
