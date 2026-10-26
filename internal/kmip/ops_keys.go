package kmip

import (
	"context"
	"encoding/base64"
	"strconv"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openbao/openbao/sdk/v2/logical"
	engine "github.com/openbao/openbao/v2/internal/builtin/logical/kmip"
)

func (o *objectOps) create(ctx context.Context, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	typ, ok := objectTypeTokens[req.ObjectType]
	if !ok {
		return nil, notSupported("object type %v is not supported", req.ObjectType)
	}
	attrs, err := templateAttributes(&req.TemplateAttribute)
	if err != nil {
		return nil, err
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "create", map[string]any{
		"object_type": typ,
		"attributes":  attrs,
	})
	if err != nil {
		return nil, err
	}

	uid := resp.Data["uid"].(string)
	kmipserver.SetIdPlaceholder(ctx, uid)
	return &payloads.CreateResponsePayload{ObjectType: req.ObjectType, UniqueIdentifier: uid}, nil
}

// formatTokens maps KMIP key format types to the engine's format names.
var formatTokens = map[kmip.KeyFormatType]string{
	kmip.KeyFormatTypeRaw:          engine.FormatRaw,
	kmip.KeyFormatTypeOpaque:       engine.FormatOpaque,
	kmip.KeyFormatTypePKCS_1:       engine.FormatPKCS1,
	kmip.KeyFormatTypePKCS_8:       engine.FormatPKCS8,
	kmip.KeyFormatTypeX_509:        engine.FormatX509,
	kmip.KeyFormatTypeECPrivateKey: engine.FormatECPrivateKey,
}

var formatByToken = invert(formatTokens)

// blockMaterial extracts the key bytes and engine format name of a key block
// supplied to Register. Wrapped keys and transparent asymmetric key formats
// are not supported.
func blockMaterial(kb *kmip.KeyBlock) (material []byte, format string, err error) {
	if kb.KeyWrappingData != nil || (kb.KeyValue != nil && kb.KeyValue.Wrapped != nil) {
		return nil, "", notSupported("wrapped key material is not supported")
	}
	if kb.KeyValue == nil || kb.KeyValue.Plain == nil {
		return nil, "", kmipserver.Errorf(kmip.ResultReasonMissingData, "key material is required")
	}

	mat := kb.KeyValue.Plain.KeyMaterial
	switch {
	case mat.Bytes != nil:
		token, ok := formatTokens[kb.KeyFormatType]
		if !ok {
			return nil, "", kmipserver.Errorf(kmip.ResultReasonKeyFormatTypeNotSupported, "key format %v is not supported", kb.KeyFormatType)
		}
		return *mat.Bytes, token, nil
	case mat.TransparentSymmetricKey != nil:
		return mat.TransparentSymmetricKey.Key, engine.FormatRaw, nil
	}
	return nil, "", kmipserver.Errorf(kmip.ResultReasonKeyFormatTypeNotSupported, "transparent key format %v is not supported", kb.KeyFormatType)
}

func (o *objectOps) register(ctx context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	typ, ok := objectTypeTokens[req.ObjectType]
	if !ok {
		return nil, notSupported("object type %v is not supported", req.ObjectType)
	}
	attrs, err := templateAttributes(&req.TemplateAttribute)
	if err != nil {
		return nil, err
	}

	var (
		block      *kmip.KeyBlock
		secretType string
		material   []byte
		format     string
	)
	switch obj := req.Object.(type) {
	case *kmip.SymmetricKey:
		block = &obj.KeyBlock
	case *kmip.PrivateKey:
		block = &obj.KeyBlock
	case *kmip.PublicKey:
		block = &obj.KeyBlock
	case *kmip.SecretData:
		block = &obj.KeyBlock
		secretType = map[kmip.SecretDataType]string{
			kmip.SecretDataTypePassword: "password",
			kmip.SecretDataTypeSeed:     "seed",
		}[obj.SecretDataType]
		if secretType == "" {
			return nil, errField("unknown secret data type %v", obj.SecretDataType)
		}
	case *kmip.OpaqueObject:
		material, format = obj.OpaqueDataValue, engine.FormatOpaque
		secretType = strconv.FormatUint(uint64(obj.OpaqueDataType), 10)
	default:
		return nil, notSupported("object %T cannot be registered", req.Object)
	}

	if block != nil {
		if material, format, err = blockMaterial(block); err != nil {
			return nil, err
		}
		// The key block describes the key; a template that disagrees is
		// caught by the engine.
		if _, set := attrs[string(kmip.AttributeNameCryptographicAlgorithm)]; !set && block.CryptographicAlgorithm != 0 {
			alg, err := attributeValueString(kmip.AttributeNameCryptographicAlgorithm, block.CryptographicAlgorithm)
			if err != nil {
				return nil, err
			}
			attrs[string(kmip.AttributeNameCryptographicAlgorithm)] = []string{alg}
		}
		if _, set := attrs[string(kmip.AttributeNameCryptographicLength)]; !set && block.CryptographicLength != 0 {
			attrs[string(kmip.AttributeNameCryptographicLength)] = []string{strconv.Itoa(int(block.CryptographicLength))}
		}
	}

	data := map[string]any{
		"object_type": typ,
		"attributes":  attrs,
		"material":    base64.StdEncoding.EncodeToString(material),
		"format":      format,
	}
	if secretType != "" {
		data["secret_type"] = secretType
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "register", data)
	if err != nil {
		return nil, err
	}

	uid := resp.Data["uid"].(string)
	kmipserver.SetIdPlaceholder(ctx, uid)
	return &payloads.RegisterResponsePayload{UniqueIdentifier: uid}, nil
}

func (o *objectOps) createKeyPair(ctx context.Context, req *payloads.CreateKeyPairRequestPayload) (*payloads.CreateKeyPairResponsePayload, error) {
	data := make(map[string]any)
	for field, tpl := range map[string]*kmip.TemplateAttribute{
		"attributes":         req.CommonTemplateAttribute,
		"private_attributes": req.PrivateKeyTemplateAttribute,
		"public_attributes":  req.PublicKeyTemplateAttribute,
	} {
		attrs, err := templateAttributes(tpl)
		if err != nil {
			return nil, err
		}
		data[field] = attrs
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "create-keypair", data)
	if err != nil {
		return nil, err
	}

	// The private key becomes the ID placeholder.
	priv := resp.Data["private_uid"].(string)
	kmipserver.SetIdPlaceholder(ctx, priv)
	return &payloads.CreateKeyPairResponsePayload{
		PrivateKeyUniqueIdentifier: priv,
		PublicKeyUniqueIdentifier:  resp.Data["public_uid"].(string),
	}, nil
}

func (o *objectOps) rekey(ctx context.Context, req *payloads.RekeyRequestPayload) (*payloads.RekeyResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if req.Offset != nil {
		return nil, notSupported("an activation offset is not supported")
	}
	attrs, err := templateAttributes(req.TemplateAttribute)
	if err != nil {
		return nil, err
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "rekey/"+uid, map[string]any{"attributes": attrs})
	if err != nil {
		return nil, err
	}

	fresh := resp.Data["uid"].(string)
	kmipserver.SetIdPlaceholder(ctx, fresh)
	return &payloads.RekeyResponsePayload{UniqueIdentifier: fresh}, nil
}

func (o *objectOps) rekeyKeyPair(ctx context.Context, req *payloads.RekeyKeyPairRequestPayload) (*payloads.RekeyKeyPairResponsePayload, error) {
	uid, err := target(ctx, req.PrivateKeyUniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if req.Offset != nil {
		return nil, notSupported("an activation offset is not supported")
	}

	data := make(map[string]any)
	for field, tpl := range map[string]*kmip.TemplateAttribute{
		"attributes":         req.CommonTemplateAttribute,
		"private_attributes": req.PrivateKeyTemplateAttribute,
		"public_attributes":  req.PublicKeyTemplateAttribute,
	} {
		attrs, err := templateAttributes(tpl)
		if err != nil {
			return nil, err
		}
		data[field] = attrs
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "rekey-keypair/"+uid, data)
	if err != nil {
		return nil, err
	}

	priv := resp.Data["private_uid"].(string)
	kmipserver.SetIdPlaceholder(ctx, priv)
	return &payloads.RekeyKeyPairResponsePayload{
		PrivateKeyUniqueIdentifier: priv,
		PublicKeyUniqueIdentifier:  resp.Data["public_uid"].(string),
	}, nil
}

func (o *objectOps) get(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if req.KeyCompressionType != 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonKeyCompressionTypeNotSupported, "key compression is not supported")
	}
	if req.KeyWrappingSpecification != nil {
		return nil, notSupported("key wrapping is not supported")
	}

	// A transparent symmetric key is the raw key in a different encoding.
	wantTransparent := req.KeyFormatType == kmip.KeyFormatTypeTransparentSymmetricKey
	format := ""
	switch {
	case wantTransparent:
		format = engine.FormatRaw
	case req.KeyFormatType != 0:
		var ok bool
		if format, ok = formatTokens[req.KeyFormatType]; !ok {
			return nil, kmipserver.Errorf(kmip.ResultReasonKeyFormatTypeNotSupported, "key format %v is not supported", req.KeyFormatType)
		}
	}

	resp, err := o.call(ctx, logical.ReadOperation, "get/"+uid, map[string]any{"format": format})
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(resp.Data["key"].(string))
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "decoding key: %v", err)
	}
	gotFormat, _ := resp.Data["format"].(string)
	objType, _ := resp.Data["object_type"].(string)
	secretType, _ := resp.Data["secret_type"].(string)
	length, _ := resp.Data["length"].(int)
	algToken, _ := resp.Data["algorithm"].(string)

	block := kmip.KeyBlock{
		KeyFormatType: formatByToken[gotFormat],
		KeyValue:      &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &key}}},
	}
	if alg, ok := algorithmByToken[algToken]; ok {
		block.CryptographicAlgorithm = alg
		block.CryptographicLength = int32(length)
	}

	out := &payloads.GetResponsePayload{
		ObjectType:       objectTypeByTok[objType],
		UniqueIdentifier: uid,
	}
	switch objType {
	case engine.TypeSymmetricKey:
		if wantTransparent {
			block.KeyFormatType = kmip.KeyFormatTypeTransparentSymmetricKey
			block.KeyValue = &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{
				TransparentSymmetricKey: &kmip.TransparentSymmetricKey{Key: key},
			}}}
		}
		out.Object = &kmip.SymmetricKey{KeyBlock: block}
	case engine.TypeSecretData:
		dataType := kmip.SecretDataTypePassword
		if secretType == "seed" {
			dataType = kmip.SecretDataTypeSeed
		}
		out.Object = &kmip.SecretData{SecretDataType: dataType, KeyBlock: block}
	case engine.TypeOpaqueObject:
		n, _ := strconv.ParseUint(secretType, 10, 32)
		out.Object = &kmip.OpaqueObject{OpaqueDataType: kmip.OpaqueDataType(n), OpaqueDataValue: key}
	case engine.TypePrivateKey:
		out.Object = &kmip.PrivateKey{KeyBlock: block}
	case engine.TypePublicKey:
		out.Object = &kmip.PublicKey{KeyBlock: block}
	default:
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "unexpected object type %q", objType)
	}
	return out, nil
}

func (o *objectOps) check(ctx context.Context, req *CheckRequestPayload) (*CheckResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	// The engine keeps no usage counters or leases, so a check of either
	// could not be honest.
	if req.UsageLimitsCount != nil || req.LeaseTime != nil {
		return nil, notSupported("usage limits and leases are not supported")
	}

	if _, err := o.call(ctx, logical.UpdateOperation, "check/"+uid, map[string]any{
		"usage_mask": int(req.CryptographicUsageMask),
	}); err != nil {
		return nil, err
	}
	return &CheckResponsePayload{UniqueIdentifier: uid, CryptographicUsageMask: req.CryptographicUsageMask}, nil
}
