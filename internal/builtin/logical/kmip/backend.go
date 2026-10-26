// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package kmip is a secrets engine that stores KMIP managed objects: their
// attributes, ownership and lifecycle state. The KMIP protocol front end
// translates TTLV messages into requests against this engine.
package kmip

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/go-uuid"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ReasonKey is the key, inside the "data" element of an error response, that
// carries the machine-readable reason of a failure. A response is still an
// error when its data holds only "error" and "data"; response headers are not
// used because the router drops them unless the mount allows them.
const ReasonKey = "kmip_reason"

// Reason returns the machine-readable reason of an error response, or "" if
// it has none.
func Reason(resp *logical.Response) string {
	data, _ := resp.Data["data"].(map[string]any)
	reason, _ := data[ReasonKey].(string)
	return reason
}

const (
	operationPrefixKMIP = "kmip"
	objectPrefix        = "object/"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	locks []*locksutil.LockEntry
	now   func() time.Time
}

func Backend() *backend {
	b := &backend{
		locks: locksutil.CreateLocks(),
		now:   time.Now,
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{objectPrefix},
		},
		Paths: []*framework.Path{
			b.pathCreate(),
			b.pathRegister(),
			b.pathCreateKeyPair(),
			b.pathRekey(),
			b.pathRekeyKeyPair(),
			b.pathGet(),
			b.pathAttributes(),
			b.pathLocate(),
			b.pathActivate(),
			b.pathRevoke(),
			b.pathDestroy(),
			b.pathCheck(),
			b.pathEncrypt(),
			b.pathDecrypt(),
			b.pathSign(),
			b.pathVerify(),
			b.pathMAC(),
			b.pathMACVerify(),
			b.pathHash(),
			b.pathRandom(),
		},
	}

	return b
}

// owner identifies who a new object belongs to. Objects are only visible to
// the entity that created them.
func owner(req *logical.Request) (string, error) {
	if req.EntityID == "" {
		return "", failf(ReasonPermissionDenied, "request has no entity; KMIP objects must have an owner")
	}
	return req.EntityID, nil
}

// failure turns an operation error into an error response carrying the
// machine-readable reason.
func failure(err error) (*logical.Response, error) {
	if oe, ok := asOpError(err); ok {
		resp := logical.ErrorResponse("%s", oe.msg)
		resp.Data["data"] = map[string]any{ReasonKey: oe.reason}
		return resp, nil
	}
	return nil, err
}

func notFound(uid string) *opError {
	return failf(ReasonItemNotFound, "object %q not found", uid)
}

// load reads an object and checks that the caller owns it. An object owned by
// someone else is reported as not found so that its existence is not leaked.
func (b *backend) load(ctx context.Context, req *logical.Request, uid string) (*Object, error) {
	who, err := owner(req)
	if err != nil {
		return nil, err
	}

	entry, err := req.Storage.Get(ctx, objectPrefix+uid)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, notFound(uid)
	}

	var obj Object
	if err := entry.DecodeJSON(&obj); err != nil {
		return nil, err
	}
	if obj.Owner != who {
		return nil, notFound(uid)
	}
	return &obj, nil
}

func (b *backend) save(ctx context.Context, req *logical.Request, obj *Object) error {
	entry, err := logical.StorageEntryJSON(objectPrefix+obj.UID, obj)
	if err != nil {
		return err
	}
	return req.Storage.Put(ctx, entry)
}

// mutate runs fn on the named object under its lock and persists the result.
func (b *backend) mutate(ctx context.Context, req *logical.Request, uid string, fn func(*Object) error) (*Object, error) {
	lock := locksutil.LockForKey(b.locks, uid)
	lock.Lock()
	defer lock.Unlock()

	obj, err := b.load(ctx, req, uid)
	if err != nil {
		return nil, err
	}
	if err := fn(obj); err != nil {
		return nil, err
	}
	if err := b.save(ctx, req, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// newBase returns a Pre-Active object owned by who, with the server-managed
// attributes set.
func (b *backend) newBase(who, typ string) (*Object, error) {
	uid, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	now := b.now()
	return &Object{
		UID:            uid,
		Owner:          who,
		Type:           typ,
		State:          StatePreActive,
		Extractable:    true,
		InitialDate:    now,
		LastChangeDate: now,
	}, nil
}

func (b *backend) lockFor(uid string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.locks, uid)
}

func asOpError(err error) (*opError, bool) {
	var oe *opError
	ok := errors.As(err, &oe)
	return oe, ok
}
