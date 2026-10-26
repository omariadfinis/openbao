// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// templateLength reads the algorithm and length a template asks for.
func templateKey(all map[string][]string) (alg string, bits int, err error) {
	if v := all[AttrCryptographicAlgorithm]; len(v) == 1 {
		alg = strings.ToLower(v[0])
	}
	v := all[AttrCryptographicLength]
	if len(v) != 1 {
		return "", 0, failf(ReasonInvalidField, "length is required")
	}
	if bits, err = strconv.Atoi(v[0]); err != nil {
		return "", 0, failf(ReasonInvalidField, "invalid length %q", v[0])
	}
	return alg, bits, nil
}

// link adds a relationship from o to another object.
func (o *Object) link(typ, uid string) {
	o.Links = append(o.Links, Link{Type: typ, UID: uid})
}

// linked returns the identifier of the first link of the given type.
func (o *Object) linked(typ string) string {
	for _, l := range o.Links {
		if l.Type == typ {
			return l.UID
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// create-keypair

func (b *backend) pathCreateKeyPair() *framework.Path {
	return &framework.Path{
		Pattern: "create-keypair",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKMIP,
			OperationVerb:   "create",
			OperationSuffix: "key-pair",
		},
		Fields: map[string]*framework.FieldSchema{
			"attributes":         attributesField("Attributes common to both keys; must include the algorithm (rsa or ecdsa) and length"),
			"private_attributes": attributesField("Attributes of the private key; override the common ones"),
			"public_attributes":  attributesField("Attributes of the public key; override the common ones"),
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleCreateKeyPair},
		},
		HelpSynopsis: "Create an asymmetric key pair as two linked objects.",
	}
}

// newPair generates a key pair and builds its two linked objects, applying
// the given attributes to each. The objects are not saved.
func (b *backend) newPair(who, alg string, bits int, privAttrs, pubAttrs map[string][]string) (priv, pub *Object, err error) {
	privDER, pubDER, err := generateKeyPair(alg, bits)
	if err != nil {
		return nil, nil, err
	}

	if priv, err = b.newBase(who, TypePrivateKey); err != nil {
		return nil, nil, err
	}
	if pub, err = b.newBase(who, TypePublicKey); err != nil {
		return nil, nil, err
	}
	priv.Algorithm, priv.Length, priv.Key = alg, bits, privDER
	pub.Algorithm, pub.Length, pub.Key = alg, bits, pubDER

	now := b.now()
	if err := priv.ApplyAttributes(now, privAttrs); err != nil {
		return nil, nil, err
	}
	if err := pub.ApplyAttributes(now, pubAttrs); err != nil {
		return nil, nil, err
	}

	priv.link(LinkPublicKey, pub.UID)
	pub.link(LinkPrivateKey, priv.UID)
	return priv, pub, nil
}

func (b *backend) handleCreateKeyPair(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	who, err := owner(req)
	if err != nil {
		return failure(err)
	}

	common, err := attrs(d, "attributes")
	if err != nil {
		return failure(err)
	}
	privOver, err := attrs(d, "private_attributes")
	if err != nil {
		return failure(err)
	}
	pubOver, err := attrs(d, "public_attributes")
	if err != nil {
		return failure(err)
	}
	privAttrs, pubAttrs := merged(common, privOver), merged(common, pubOver)

	alg, bits, err := templateKey(merged(privAttrs, pubAttrs))
	if err != nil {
		return failure(err)
	}

	priv, pub, err := b.newPair(who, alg, bits, privAttrs, pubAttrs)
	if err != nil {
		return failure(err)
	}

	if err := b.atomic(ctx, req, func() error {
		if err := b.save(ctx, req, priv); err != nil {
			return err
		}
		return b.save(ctx, req, pub)
	}); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{"private_uid": priv.UID, "public_uid": pub.UID}}, nil
}

// ---------------------------------------------------------------------------
// rekey

// inherited returns the attributes a replacement key takes over from the key
// it replaces. The name is not inherited, as names identify one object; a
// template can give the new key a name.
func (o *Object) inherited() map[string][]string {
	attrs := map[string][]string{
		AttrCryptographicUsageMask: {strconv.Itoa(int(o.UsageMask))},
		AttrExtractable:            {strconv.FormatBool(o.Extractable)},
		AttrSensitive:              {strconv.FormatBool(o.Sensitive)},
	}
	if len(o.ObjectGroups) > 0 {
		attrs[AttrObjectGroup] = slices.Clone(o.ObjectGroups)
	}
	if o.Description != "" {
		attrs[AttrDescription] = []string{o.Description}
	}
	if o.Comment != "" {
		attrs[AttrComment] = []string{o.Comment}
	}
	for name, values := range o.Custom {
		attrs[name] = slices.Clone(values)
	}
	return attrs
}

func (b *backend) pathRekey() *framework.Path {
	return b.transitionPath("rekey", b.handleRekey, map[string]*framework.FieldSchema{
		"attributes": attributesField("Attributes that override those inherited from the old key"),
	})
}

// handleRekey replaces a symmetric key with a fresh one of the same kind. The
// old key is left as it is, linked to its replacement, so that data it
// protected can still be read.
func (b *backend) handleRekey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	who, err := owner(req)
	if err != nil {
		return failure(err)
	}
	template, err := attrs(d, "attributes")
	if err != nil {
		return failure(err)
	}

	var fresh *Object
	err = b.atomic(ctx, req, func() error {
		_, err := b.mutate(ctx, req, d.Get("uid").(string), func(old *Object) error {
			if old.Type != TypeSymmetricKey {
				return failf(ReasonIllegalOperation, "only symmetric keys are re-keyed this way; use re-key key pair for asymmetric keys")
			}
			if old.Destroyed() {
				return failf(ReasonIllegalOperation, "object is %s and cannot be re-keyed", old.State)
			}

			key, err := generateSymmetric(old.Algorithm, old.Length)
			if err != nil {
				return err
			}
			if fresh, err = b.newBase(who, TypeSymmetricKey); err != nil {
				return err
			}
			fresh.Algorithm, fresh.Length, fresh.Key = old.Algorithm, old.Length, key
			if err := fresh.ApplyAttributes(b.now(), merged(old.inherited(), template)); err != nil {
				return err
			}

			fresh.link(LinkReplaced, old.UID)
			old.link(LinkReplacement, fresh.UID)
			old.LastChangeDate = b.now()
			return b.save(ctx, req, fresh)
		})
		return err
	})
	if err != nil {
		return failure(err)
	}

	return &logical.Response{Data: map[string]any{"uid": fresh.UID, "state": fresh.State}}, nil
}

// ---------------------------------------------------------------------------
// rekey-keypair

func (b *backend) pathRekeyKeyPair() *framework.Path {
	return b.transitionPath("rekey-keypair", b.handleRekeyKeyPair, map[string]*framework.FieldSchema{
		"attributes":         attributesField("Attributes common to both new keys"),
		"private_attributes": attributesField("Attributes of the new private key"),
		"public_attributes":  attributesField("Attributes of the new public key"),
	})
}

// handleRekeyKeyPair replaces a key pair, named by its private key, with a
// fresh pair of the same kind. The old pair stays, linked to the new one.
func (b *backend) handleRekeyKeyPair(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	who, err := owner(req)
	if err != nil {
		return failure(err)
	}
	common, err := attrs(d, "attributes")
	if err != nil {
		return failure(err)
	}
	privOver, err := attrs(d, "private_attributes")
	if err != nil {
		return failure(err)
	}
	pubOver, err := attrs(d, "public_attributes")
	if err != nil {
		return failure(err)
	}

	var newPriv, newPub *Object
	err = b.atomic(ctx, req, func() error {
		_, err := b.mutate(ctx, req, d.Get("uid").(string), func(oldPriv *Object) error {
			if oldPriv.Type != TypePrivateKey {
				return failf(ReasonIllegalOperation, "object is not a private key; name the private key of the pair")
			}
			if oldPriv.Destroyed() {
				return failf(ReasonIllegalOperation, "object is %s and cannot be re-keyed", oldPriv.State)
			}

			// The public key is optional: it may have been destroyed or
			// belong to the pair only by link.
			var oldPub *Object
			if pubUID := oldPriv.linked(LinkPublicKey); pubUID != "" {
				if oldPub, err = b.load(ctx, req, pubUID); err != nil {
					return err
				}
			}

			privAttrs := merged(oldPriv.inherited(), merged(common, privOver))
			pubInherited := map[string][]string{}
			if oldPub != nil {
				pubInherited = oldPub.inherited()
			}
			pubAttrs := merged(pubInherited, merged(common, pubOver))

			if newPriv, newPub, err = b.newPair(who, oldPriv.Algorithm, oldPriv.Length, privAttrs, pubAttrs); err != nil {
				return err
			}

			now := b.now()
			newPriv.link(LinkReplaced, oldPriv.UID)
			oldPriv.link(LinkReplacement, newPriv.UID)
			oldPriv.LastChangeDate = now
			if oldPub != nil {
				newPub.link(LinkReplaced, oldPub.UID)
				oldPub.link(LinkReplacement, newPub.UID)
				oldPub.LastChangeDate = now
				if err := b.save(ctx, req, oldPub); err != nil {
					return err
				}
			}

			if err := b.save(ctx, req, newPriv); err != nil {
				return err
			}
			return b.save(ctx, req, newPub)
		})
		return err
	})
	if err != nil {
		return failure(err)
	}

	return &logical.Response{Data: map[string]any{"private_uid": newPriv.UID, "public_uid": newPub.UID}}, nil
}
