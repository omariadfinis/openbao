// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var uidField = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Unique identifier of the object",
}

// attributesField carries KMIP attributes as name to value(s).
func attributesField(desc string) *framework.FieldSchema {
	return &framework.FieldSchema{Type: framework.TypeMap, Description: desc}
}

// parseAttributes reads an attribute map whose values are a string or a list
// of strings. Numbers and booleans, which arrive when the request came in as
// JSON, are accepted and stringified.
func parseAttributes(raw map[string]any) (map[string][]string, error) {
	out := make(map[string][]string, len(raw))
	for name, v := range raw {
		switch v := v.(type) {
		case string:
			out[name] = []string{v}
		case []string:
			out[name] = slices.Clone(v)
		case []any:
			for _, item := range v {
				s, err := scalar(item)
				if err != nil {
					return nil, failf(ReasonInvalidField, "attribute %q: %v", name, err)
				}
				out[name] = append(out[name], s)
			}
		default:
			s, err := scalar(v)
			if err != nil {
				return nil, failf(ReasonInvalidField, "attribute %q: %v", name, err)
			}
			out[name] = []string{s}
		}
	}
	return out, nil
}

func scalar(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int32:
		return strconv.Itoa(int(v)), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case float64:
		return strconv.FormatInt(int64(v), 10), nil
	}
	return "", fmt.Errorf("unsupported value of type %T", v)
}

// attrs reads the named attribute-map field.
func attrs(d *framework.FieldData, field string) (map[string][]string, error) {
	raw, _ := d.Get(field).(map[string]any)
	return parseAttributes(raw)
}

// merged returns base overlaid with over.
func merged(base, over map[string][]string) map[string][]string {
	out := make(map[string][]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// atomic runs fn in a storage transaction where one is available, so that an
// operation which writes several objects either writes all of them or none.
func (b *backend) atomic(ctx context.Context, req *logical.Request, fn func() error) error {
	rollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return err
	}
	defer rollback()

	if err := fn(); err != nil {
		return err
	}
	return logical.EndTxStorage(ctx, req)
}

// ---------------------------------------------------------------------------
// create

func (b *backend) pathCreate() *framework.Path {
	return &framework.Path{
		Pattern: "create",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "create",
			OperationSuffix: "object",
		},
		Fields: map[string]*framework.FieldSchema{
			"object_type": {Type: framework.TypeString, Default: TypeSymmetricKey, Description: "Type of object to create; only symmetric-key is supported"},
			"attributes":  attributesField("KMIP attributes of the new object"),
			"algorithm":   {Type: framework.TypeString, Description: "Cryptographic algorithm: aes or hmac-sha1/224/256/384/512 (shorthand for the attribute)"},
			"length":      {Type: framework.TypeInt, Description: "Key length in bits (shorthand for the attribute)"},
			"usage_mask":  {Type: framework.TypeInt, Description: "KMIP cryptographic usage mask (shorthand for the attribute)"},
			"name":        {Type: framework.TypeString, Description: "Name attribute (shorthand)"},
			"description": {Type: framework.TypeString, Description: "Description attribute (shorthand)"},
			"extractable": {Type: framework.TypeBool, Description: "Extractable attribute (shorthand)"},
			"sensitive":   {Type: framework.TypeBool, Description: "Sensitive attribute (shorthand)"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleCreate},
		},
		HelpSynopsis: "Create a managed object with generated key material.",
	}
}

// shorthand collects the single-field forms of common attributes.
func shorthand(d *framework.FieldData) map[string][]string {
	out := make(map[string][]string)
	set := func(field, attr string, conv func(any) string) {
		if v, ok := d.GetOk(field); ok {
			out[attr] = []string{conv(v)}
		}
	}
	str := func(v any) string { return v.(string) }
	set("algorithm", AttrCryptographicAlgorithm, str)
	set("length", AttrCryptographicLength, func(v any) string { return strconv.Itoa(v.(int)) })
	set("usage_mask", AttrCryptographicUsageMask, func(v any) string { return strconv.Itoa(v.(int)) })
	set("name", AttrName, str)
	set("description", AttrDescription, str)
	set("extractable", AttrExtractable, func(v any) string { return strconv.FormatBool(v.(bool)) })
	set("sensitive", AttrSensitive, func(v any) string { return strconv.FormatBool(v.(bool)) })
	return out
}

func (b *backend) handleCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	who, err := owner(req)
	if err != nil {
		return failure(err)
	}
	if t := d.Get("object_type").(string); t != TypeSymmetricKey {
		return failure(failf(ReasonFeatureNotSupported, "object type %q cannot be created; register it instead", t))
	}

	given, err := attrs(d, "attributes")
	if err != nil {
		return failure(err)
	}
	all := merged(shorthand(d), given)

	alg := AlgAES
	if v := all[AttrCryptographicAlgorithm]; len(v) == 1 {
		alg = strings.ToLower(v[0])
	}
	if len(all[AttrCryptographicLength]) != 1 {
		return failure(failf(ReasonInvalidField, "length is required"))
	}
	bits, err := strconv.Atoi(all[AttrCryptographicLength][0])
	if err != nil {
		return failure(failf(ReasonInvalidField, "invalid length %q", all[AttrCryptographicLength][0]))
	}

	key, err := generateSymmetric(alg, bits)
	if err != nil {
		return failure(err)
	}

	obj, err := b.newBase(who, TypeSymmetricKey)
	if err != nil {
		return nil, err
	}
	obj.Algorithm, obj.Length, obj.Key = alg, bits, key
	if err := obj.ApplyAttributes(b.now(), all); err != nil {
		return failure(err)
	}
	if err := b.save(ctx, req, obj); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{"uid": obj.UID, "state": obj.State}}, nil
}

// ---------------------------------------------------------------------------
// register

func (b *backend) pathRegister() *framework.Path {
	return &framework.Path{
		Pattern: "register",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "register",
			OperationSuffix: "object",
		},
		Fields: map[string]*framework.FieldSchema{
			"object_type": {Type: framework.TypeString, Description: "symmetric-key, secret-data, opaque-object, private-key or public-key"},
			"attributes":  attributesField("KMIP attributes of the new object"),
			"material":    {Type: framework.TypeString, Description: "Base64-encoded key material"},
			"format":      {Type: framework.TypeString, Description: "Format of the material: raw, opaque, pkcs1, pkcs8, x509 or ec-private-key"},
			"secret_type": {Type: framework.TypeString, Description: "Secret data type (password or seed, default password), or the numeric opaque data type of an opaque object"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleRegister},
		},
		HelpSynopsis: "Register existing key material as a managed object.",
	}
}

func (b *backend) handleRegister(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	who, err := owner(req)
	if err != nil {
		return failure(err)
	}

	typ := d.Get("object_type").(string)
	given, err := attrs(d, "attributes")
	if err != nil {
		return failure(err)
	}
	material, err := decodeField(d, "material")
	if err != nil {
		return failure(err)
	}

	var alg string
	if v := given[AttrCryptographicAlgorithm]; len(v) == 1 {
		alg = strings.ToLower(v[0])
	}
	var bits int
	if v := given[AttrCryptographicLength]; len(v) == 1 {
		if bits, err = strconv.Atoi(v[0]); err != nil {
			return failure(failf(ReasonInvalidField, "invalid length %q", v[0]))
		}
	}

	outAlg, outBits, key, err := parseRegistered(typ, material, d.Get("format").(string), alg, bits)
	if err != nil {
		return failure(err)
	}

	obj, err := b.newBase(who, typ)
	if err != nil {
		return nil, err
	}
	obj.Algorithm, obj.Length, obj.Key = outAlg, outBits, key

	secretType := d.Get("secret_type").(string)
	switch typ {
	case TypeSecretData:
		if secretType == "" {
			secretType = "password"
		}
		if secretType != "password" && secretType != "seed" {
			return failure(failf(ReasonInvalidField, "unknown secret data type %q", secretType))
		}
		obj.SecretType = secretType
	case TypeOpaqueObject:
		if secretType != "" {
			if _, err := strconv.ParseUint(secretType, 10, 32); err != nil {
				return failure(failf(ReasonInvalidField, "invalid opaque data type %q", secretType))
			}
			obj.SecretType = secretType
		}
	}

	if err := obj.ApplyAttributes(b.now(), given); err != nil {
		return failure(err)
	}
	if err := b.save(ctx, req, obj); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{"uid": obj.UID, "state": obj.State}}, nil
}

// ---------------------------------------------------------------------------
// get

func (b *backend) pathGet() *framework.Path {
	return &framework.Path{
		Pattern: "get/" + framework.GenericNameRegex("uid"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "get",
			OperationSuffix: "object",
		},
		Fields: map[string]*framework.FieldSchema{
			"uid":    uidField,
			"format": {Type: framework.TypeString, Description: "Requested key format; defaults to the natural format of the object type"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleGet},
		},
		HelpSynopsis: "Retrieve a managed object and its key material.",
	}
}

func (b *backend) handleGet(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lock := b.lockFor(d.Get("uid").(string))
	lock.RLock()
	defer lock.RUnlock()

	obj, err := b.load(ctx, req, d.Get("uid").(string))
	if err != nil {
		return failure(err)
	}

	switch {
	case obj.Destroyed():
		return failure(failf(ReasonKeyValueNotPresent, "object is %s; its key material is gone", obj.State))
	case obj.Sensitive:
		return failure(failf(ReasonSensitive, "object is sensitive"))
	case !obj.Extractable:
		return failure(failf(ReasonNotExtractable, "object is not extractable"))
	}

	format := d.Get("format").(string)
	material, err := obj.Export(format)
	if err != nil {
		return failure(err)
	}
	if format == "" {
		format = defaultFormat(obj.Type)
	}

	return &logical.Response{Data: map[string]any{
		"uid":         obj.UID,
		"object_type": obj.Type,
		"algorithm":   obj.Algorithm,
		"length":      obj.Length,
		"secret_type": obj.SecretType,
		"format":      format,
		"key":         base64.StdEncoding.EncodeToString(material),
	}}, nil
}

// ---------------------------------------------------------------------------
// attributes

func (b *backend) pathAttributes() *framework.Path {
	return &framework.Path{
		Pattern: "attributes/" + framework.GenericNameRegex("uid"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationSuffix: "attributes",
		},
		Fields: map[string]*framework.FieldSchema{
			"uid":    uidField,
			"action": {Type: framework.TypeString, Description: "add, modify or delete"},
			"name":   {Type: framework.TypeString, Description: "Attribute name"},
			"value":  {Type: framework.TypeString, Description: "Attribute value"},
			"index":  {Type: framework.TypeInt, Default: -1, Description: "Attribute instance index"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleAttributesRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleAttributesWrite},
		},
		HelpSynopsis: "Read or change the attributes of a managed object.",
	}
}

func (b *backend) handleAttributesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lock := b.lockFor(d.Get("uid").(string))
	lock.RLock()
	defer lock.RUnlock()

	obj, err := b.load(ctx, req, d.Get("uid").(string))
	if err != nil {
		return failure(err)
	}

	out := make(map[string]any)
	for name, values := range obj.Attributes() {
		out[name] = values
	}
	return &logical.Response{Data: map[string]any{"uid": obj.UID, "attributes": out}}, nil
}

func (b *backend) handleAttributesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var values []string
	name := d.Get("name").(string)

	obj, err := b.mutate(ctx, req, d.Get("uid").(string), func(o *Object) error {
		var err error
		values, err = o.Mutate(b.now(), d.Get("action").(string), name, d.Get("value").(string), d.Get("index").(int))
		return err
	})
	if err != nil {
		return failure(err)
	}

	return &logical.Response{Data: map[string]any{"uid": obj.UID, "name": name, "values": values}}, nil
}

// ---------------------------------------------------------------------------
// locate

func (b *backend) pathLocate() *framework.Path {
	return &framework.Path{
		Pattern: "locate",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "locate",
			OperationSuffix: "objects",
		},
		Fields: map[string]*framework.FieldSchema{
			"filters":   {Type: framework.TypeStringSlice, Description: "Attribute filters of the form \"Attribute Name=value\"; all must match"},
			"max_items": {Type: framework.TypeInt, Description: "Maximum number of identifiers to return; 0 for no limit"},
			"offset":    {Type: framework.TypeInt, Description: "Number of matching identifiers to skip"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleLocate},
		},
		HelpSynopsis: "Find managed objects by attribute.",
	}
}

func (b *backend) handleLocate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	who, err := owner(req)
	if err != nil {
		return failure(err)
	}

	filters := make(map[string][]string)
	for _, f := range d.Get("filters").([]string) {
		name, value, ok := strings.Cut(f, "=")
		if !ok || name == "" {
			return failure(failf(ReasonInvalidField, "invalid filter %q; expected \"Attribute Name=value\"", f))
		}
		filters[name] = append(filters[name], value)
	}

	ids, err := req.Storage.List(ctx, objectPrefix)
	if err != nil {
		return nil, err
	}

	var matched []string
	for _, id := range ids {
		obj, err := b.load(ctx, req, id)
		if err != nil {
			if oe, ok := asOpError(err); ok && oe.reason == ReasonItemNotFound {
				continue // owned by someone else
			}
			return nil, err
		}
		if obj.Owner == who && obj.Matches(filters) {
			matched = append(matched, obj.UID)
		}
	}

	total := len(matched)
	offset := d.Get("offset").(int)
	if offset > len(matched) {
		offset = len(matched)
	}
	matched = matched[offset:]
	if limit := d.Get("max_items").(int); limit > 0 && limit < len(matched) {
		matched = matched[:limit]
	}

	return &logical.Response{Data: map[string]any{"uids": matched, "located_items": total}}, nil
}

// ---------------------------------------------------------------------------
// lifecycle

func (b *backend) pathActivate() *framework.Path {
	return b.transitionPath("activate", b.handleActivate, nil)
}

func (b *backend) pathRevoke() *framework.Path {
	return b.transitionPath("revoke", b.handleRevoke, map[string]*framework.FieldSchema{
		"reason_code":                {Type: framework.TypeString, Default: "unspecified", Description: "Revocation reason code"},
		"message":                    {Type: framework.TypeString, Description: "Revocation message"},
		"compromise_occurrence_date": {Type: framework.TypeTime, Description: "When the compromise occurred (RFC 3339)"},
	})
}

func (b *backend) pathDestroy() *framework.Path {
	return b.transitionPath("destroy", b.handleDestroy, nil)
}

func (b *backend) transitionPath(verb string, cb framework.OperationFunc, extra map[string]*framework.FieldSchema) *framework.Path {
	fields := map[string]*framework.FieldSchema{"uid": uidField}
	for k, v := range extra {
		fields[k] = v
	}
	return &framework.Path{
		Pattern: verb + "/" + framework.GenericNameRegex("uid"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   verb,
			OperationSuffix: "object",
		},
		Fields: fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: cb},
		},
		HelpSynopsis: "Change the lifecycle state of a managed object (" + verb + ").",
	}
}

func (b *backend) transition(ctx context.Context, req *logical.Request, d *framework.FieldData, fn func(*Object) error) (*logical.Response, error) {
	obj, err := b.mutate(ctx, req, d.Get("uid").(string), fn)
	if err != nil {
		return failure(err)
	}
	return &logical.Response{Data: map[string]any{"uid": obj.UID, "state": obj.State}}, nil
}

func (b *backend) handleActivate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.transition(ctx, req, d, func(o *Object) error { return o.Activate(b.now()) })
}

func (b *backend) handleRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	occurrence, _ := d.Get("compromise_occurrence_date").(time.Time)
	return b.transition(ctx, req, d, func(o *Object) error {
		return o.Revoke(b.now(), d.Get("reason_code").(string), d.Get("message").(string), occurrence)
	})
}

func (b *backend) handleDestroy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.transition(ctx, req, d, func(o *Object) error { return o.Destroy(b.now()) })
}

// ---------------------------------------------------------------------------
// check

func (b *backend) pathCheck() *framework.Path {
	return &framework.Path{
		Pattern: "check/" + framework.GenericNameRegex("uid"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "check",
			OperationSuffix: "object",
		},
		Fields: map[string]*framework.FieldSchema{
			"uid":        uidField,
			"usage_mask": {Type: framework.TypeInt, Description: "Usage mask bits the object must allow"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleCheck},
		},
		HelpSynopsis: "Check that an object is usable for the given cryptographic usage.",
	}
}

// handleCheck verifies that the object is Active and permits every requested
// usage. A usage mask of zero checks the state alone.
func (b *backend) handleCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lock := b.lockFor(d.Get("uid").(string))
	lock.RLock()
	defer lock.RUnlock()

	obj, err := b.load(ctx, req, d.Get("uid").(string))
	if err != nil {
		return failure(err)
	}
	if err := obj.checkUsable(int32(d.Get("usage_mask").(int)), StateActive); err != nil {
		return failure(err)
	}
	return &logical.Response{Data: map[string]any{"uid": obj.UID}}, nil
}
