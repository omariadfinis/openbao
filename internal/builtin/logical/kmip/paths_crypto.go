// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// maxRandomBytes caps a single random request.
const maxRandomBytes = 64 * 1024

// decodeField decodes an optional base64 field.
func decodeField(d *framework.FieldData, name string) ([]byte, error) {
	raw := d.Get(name).(string)
	if raw == "" {
		return nil, nil
	}
	out, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, failf(ReasonInvalidField, "%s is not valid base64", name)
	}
	return out, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// cryptoPath builds a path that applies a managed key to some data.
func (b *backend) cryptoPath(verb string, cb framework.OperationFunc, extra map[string]*framework.FieldSchema) *framework.Path {
	fields := map[string]*framework.FieldSchema{
		"uid":  uidField,
		"data": {Type: framework.TypeString, Description: "Base64-encoded input"},
	}
	for k, v := range extra {
		fields[k] = v
	}
	return &framework.Path{
		Pattern: verb + "/" + framework.GenericNameRegex("uid"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   verb,
		},
		Fields: fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: cb},
		},
		HelpSynopsis: "Apply a managed key: " + verb + ".",
	}
}

// withKey loads the object under a read lock and runs fn on it.
func (b *backend) withKey(ctx context.Context, req *logical.Request, d *framework.FieldData, fn func(*Object) (map[string]any, error)) (*logical.Response, error) {
	uid := d.Get("uid").(string)
	lock := b.lockFor(uid)
	lock.RLock()
	defer lock.RUnlock()

	obj, err := b.load(ctx, req, uid)
	if err != nil {
		return failure(err)
	}
	data, err := fn(obj)
	if err != nil {
		return failure(err)
	}
	data["uid"] = obj.UID
	return &logical.Response{Data: data}, nil
}

// ---------------------------------------------------------------------------
// encrypt, decrypt

func (b *backend) pathEncrypt() *framework.Path {
	return b.cryptoPath("encrypt", b.handleEncrypt, map[string]*framework.FieldSchema{
		"aad":        {Type: framework.TypeString, Description: "Base64-encoded additional authenticated data"},
		"tag_length": {Type: framework.TypeInt, Description: "Authentication tag length in bytes, 12 to 16; defaults to 16"},
	})
}

func (b *backend) pathDecrypt() *framework.Path {
	return b.cryptoPath("decrypt", b.handleDecrypt, map[string]*framework.FieldSchema{
		"aad": {Type: framework.TypeString, Description: "Base64-encoded additional authenticated data"},
		"iv":  {Type: framework.TypeString, Description: "Base64-encoded nonce returned by encrypt"},
		"tag": {Type: framework.TypeString, Description: "Base64-encoded authentication tag returned by encrypt"},
	})
}

func (b *backend) handleEncrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	aad, err := decodeField(d, "aad")
	if err != nil {
		return failure(err)
	}

	return b.withKey(ctx, req, d, func(o *Object) (map[string]any, error) {
		ct, nonce, tag, err := o.Encrypt(data, aad, d.Get("tag_length").(int))
		if err != nil {
			return nil, err
		}
		return map[string]any{"data": b64(ct), "iv": b64(nonce), "tag": b64(tag)}, nil
	})
}

func (b *backend) handleDecrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	aad, err := decodeField(d, "aad")
	if err != nil {
		return failure(err)
	}
	nonce, err := decodeField(d, "iv")
	if err != nil {
		return failure(err)
	}
	tag, err := decodeField(d, "tag")
	if err != nil {
		return failure(err)
	}
	if len(nonce) == 0 || len(tag) == 0 {
		return failure(failf(ReasonMissingData, "iv and tag are required"))
	}

	return b.withKey(ctx, req, d, func(o *Object) (map[string]any, error) {
		plaintext, err := o.Decrypt(data, nonce, tag, aad)
		if err != nil {
			return nil, err
		}
		return map[string]any{"data": b64(plaintext)}, nil
	})
}

// ---------------------------------------------------------------------------
// sign, verify

var signFields = map[string]*framework.FieldSchema{
	"hash":        {Type: framework.TypeString, Default: "sha256", Description: "Hash algorithm: sha224, sha256, sha384 or sha512"},
	"padding":     {Type: framework.TypeString, Description: "RSA padding: pkcs1v15 (default) or pss"},
	"salt_length": {Type: framework.TypeInt, Description: "PSS salt length in bytes; defaults to the hash length"},
	"prehashed":   {Type: framework.TypeBool, Description: "Whether data is already a digest"},
}

func signParams(d *framework.FieldData) SignParams {
	return SignParams{
		Hash:       d.Get("hash").(string),
		Padding:    d.Get("padding").(string),
		SaltLength: d.Get("salt_length").(int),
		Prehashed:  d.Get("prehashed").(bool),
	}
}

func withSignFields(extra map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	out := make(map[string]*framework.FieldSchema, len(signFields)+len(extra))
	for k, v := range signFields {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (b *backend) pathSign() *framework.Path {
	return b.cryptoPath("sign", b.handleSign, withSignFields(nil))
}

func (b *backend) pathVerify() *framework.Path {
	return b.cryptoPath("verify", b.handleVerify, withSignFields(map[string]*framework.FieldSchema{
		"signature": {Type: framework.TypeString, Description: "Base64-encoded signature"},
	}))
}

func (b *backend) handleSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	return b.withKey(ctx, req, d, func(o *Object) (map[string]any, error) {
		sig, err := o.Sign(data, signParams(d))
		if err != nil {
			return nil, err
		}
		return map[string]any{"signature": b64(sig)}, nil
	})
}

func (b *backend) handleVerify(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	sig, err := decodeField(d, "signature")
	if err != nil {
		return failure(err)
	}
	if len(sig) == 0 {
		return failure(failf(ReasonMissingData, "signature is required"))
	}
	return b.withKey(ctx, req, d, func(o *Object) (map[string]any, error) {
		valid, err := o.Verify(data, sig, signParams(d))
		if err != nil {
			return nil, err
		}
		return map[string]any{"valid": valid}, nil
	})
}

// ---------------------------------------------------------------------------
// mac, mac-verify

func (b *backend) pathMAC() *framework.Path {
	return b.cryptoPath("mac", b.handleMAC, map[string]*framework.FieldSchema{
		"hash": {Type: framework.TypeString, Description: "Hash of the HMAC; must match the key's algorithm if given"},
	})
}

func (b *backend) pathMACVerify() *framework.Path {
	return b.cryptoPath("mac-verify", b.handleMACVerify, map[string]*framework.FieldSchema{
		"hash": {Type: framework.TypeString, Description: "Hash of the HMAC; must match the key's algorithm if given"},
		"mac":  {Type: framework.TypeString, Description: "Base64-encoded MAC to check"},
	})
}

func (b *backend) handleMAC(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	return b.withKey(ctx, req, d, func(o *Object) (map[string]any, error) {
		mac, err := o.MAC(data, d.Get("hash").(string))
		if err != nil {
			return nil, err
		}
		return map[string]any{"mac": b64(mac)}, nil
	})
}

func (b *backend) handleMACVerify(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	mac, err := decodeField(d, "mac")
	if err != nil {
		return failure(err)
	}
	if len(mac) == 0 {
		return failure(failf(ReasonMissingData, "mac is required"))
	}
	return b.withKey(ctx, req, d, func(o *Object) (map[string]any, error) {
		valid, err := o.VerifyMAC(data, mac, d.Get("hash").(string))
		if err != nil {
			return nil, err
		}
		return map[string]any{"valid": valid}, nil
	})
}

// ---------------------------------------------------------------------------
// hash, random

func (b *backend) pathHash() *framework.Path {
	return &framework.Path{
		Pattern: "hash",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "hash",
		},
		Fields: map[string]*framework.FieldSchema{
			"hash": {Type: framework.TypeString, Default: "sha256", Description: "Hash algorithm: sha224, sha256, sha384 or sha512"},
			"data": {Type: framework.TypeString, Description: "Base64-encoded input"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHash},
		},
		HelpSynopsis: "Hash data; no key is involved.",
	}
}

func (b *backend) handleHash(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	data, err := decodeField(d, "data")
	if err != nil {
		return failure(err)
	}
	h, err := hashFor(d.Get("hash").(string))
	if err != nil {
		return failure(err)
	}
	sum, err := digest(h, data, false)
	if err != nil {
		return failure(err)
	}
	return &logical.Response{Data: map[string]any{"data": b64(sum)}}, nil
}

func (b *backend) pathRandom() *framework.Path {
	return &framework.Path{
		Pattern: "random",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "random",
		},
		Fields: map[string]*framework.FieldSchema{
			"length": {Type: framework.TypeInt, Description: "Number of random bytes to return"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleRandom},
		},
		HelpSynopsis: "Return random bytes.",
	}
}

func (b *backend) handleRandom(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	n := d.Get("length").(int)
	if n <= 0 || n > maxRandomBytes {
		return failure(failf(ReasonInvalidField, "length must be between 1 and %d bytes", maxRandomBytes))
	}
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"data": b64(out)}}, nil
}
