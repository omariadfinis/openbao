// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/sdk/v2/logical"
)

type harness struct {
	t       *testing.T
	b       *backend
	storage logical.Storage
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	b := Backend()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	require.NoError(t, b.Setup(t.Context(), conf))
	return &harness{t: t, b: b, storage: conf.StorageView}
}

func (h *harness) do(entity string, op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
	h.t.Helper()
	return h.b.HandleRequest(h.t.Context(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   h.storage,
		EntityID:  entity,
	})
}

// ok runs a request that must succeed.
func (h *harness) ok(entity string, op logical.Operation, path string, data map[string]any) *logical.Response {
	h.t.Helper()
	resp, err := h.do(entity, op, path, data)
	require.NoError(h.t, err)
	require.False(h.t, resp.IsError(), "%s: %v", path, resp.Error())
	return resp
}

// fails runs a request that must be refused with the given KMIP reason.
func (h *harness) fails(reason, entity string, op logical.Operation, path string, data map[string]any) {
	h.t.Helper()
	resp, err := h.do(entity, op, path, data)
	require.NoError(h.t, err)
	require.True(h.t, resp.IsError(), "%s should have failed", path)
	require.Equal(h.t, reason, Reason(resp), resp.Error())
}

func (h *harness) create(entity string, extra map[string]any) string {
	h.t.Helper()
	data := map[string]any{"length": 256, "usage_mask": 12}
	for k, v := range extra {
		data[k] = v
	}
	return h.ok(entity, logical.UpdateOperation, "create", data).Data["uid"].(string)
}

func TestCreate(t *testing.T) {
	h := newHarness(t)

	uid := h.create("alice", map[string]any{"name": "disk-key"})
	attrs := h.ok("alice", logical.ReadOperation, "attributes/"+uid, nil).Data["attributes"].(map[string]any)

	require.Equal(t, []string{"pre-active"}, attrs[AttrState])
	require.Equal(t, []string{"256"}, attrs[AttrCryptographicLength])
	require.Equal(t, []string{"aes"}, attrs[AttrCryptographicAlgorithm])
	require.Equal(t, []string{"disk-key"}, attrs[AttrName])
	require.Equal(t, []string{"12"}, attrs[AttrCryptographicUsageMask])

	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "create", map[string]any{"length": 100})
	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "create", nil)
	h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "create", map[string]any{"length": 256, "algorithm": "des"})
	h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, "create", map[string]any{"length": 256, "object_type": "certificate"})
}

func TestCreate_RequiresEntity(t *testing.T) {
	h := newHarness(t)
	h.fails(ReasonPermissionDenied, "", logical.UpdateOperation, "create", map[string]any{"length": 256})
	h.fails(ReasonPermissionDenied, "", logical.UpdateOperation, "locate", nil)
}

func TestGet(t *testing.T) {
	h := newHarness(t)
	uid := h.create("alice", map[string]any{"length": 128})

	resp := h.ok("alice", logical.ReadOperation, "get/"+uid, nil)
	key, err := base64.StdEncoding.DecodeString(resp.Data["key"].(string))
	require.NoError(t, err)
	require.Len(t, key, 16)

	// Two keys never share material.
	other := h.create("alice", map[string]any{"length": 128})
	otherKey := h.ok("alice", logical.ReadOperation, "get/"+other, nil).Data["key"]
	require.NotEqual(t, resp.Data["key"], otherKey)

	h.fails(ReasonItemNotFound, "alice", logical.ReadOperation, "get/does-not-exist", nil)
}

func TestGet_NotExtractableAndSensitive(t *testing.T) {
	h := newHarness(t)

	locked := h.create("alice", map[string]any{"extractable": false})
	h.fails(ReasonNotExtractable, "alice", logical.ReadOperation, "get/"+locked, nil)

	sensitive := h.create("alice", map[string]any{"sensitive": true})
	h.fails(ReasonSensitive, "alice", logical.ReadOperation, "get/"+sensitive, nil)

	// Sensitive can be turned on later, but not off again.
	plain := h.create("alice", nil)
	h.ok("alice", logical.UpdateOperation, "attributes/"+plain, map[string]any{"action": "modify", "name": AttrSensitive, "value": "true"})
	h.fails(ReasonSensitive, "alice", logical.ReadOperation, "get/"+plain, nil)
	h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "attributes/"+plain, map[string]any{"action": "modify", "name": AttrSensitive, "value": "false"})
}

func TestOwnership(t *testing.T) {
	h := newHarness(t)
	uid := h.create("alice", map[string]any{"name": "alice-key"})

	// Another entity cannot see, read, change or locate the object, and
	// cannot tell it exists.
	h.fails(ReasonItemNotFound, "bob", logical.ReadOperation, "get/"+uid, nil)
	h.fails(ReasonItemNotFound, "bob", logical.ReadOperation, "attributes/"+uid, nil)
	h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "activate/"+uid, nil)
	h.fails(ReasonItemNotFound, "bob", logical.UpdateOperation, "destroy/"+uid, nil)

	require.Empty(t, h.ok("bob", logical.UpdateOperation, "locate", nil).Data["uids"])
	require.Equal(t, []string{uid}, h.ok("alice", logical.UpdateOperation, "locate", nil).Data["uids"])

	// The object is untouched by bob's attempts.
	attrs := h.ok("alice", logical.ReadOperation, "attributes/"+uid, nil).Data["attributes"].(map[string]any)
	require.Equal(t, []string{"pre-active"}, attrs[AttrState])
}

func TestLifecycle(t *testing.T) {
	h := newHarness(t)
	state := func(uid string) string {
		attrs := h.ok("alice", logical.ReadOperation, "attributes/"+uid, nil).Data["attributes"].(map[string]any)
		return attrs[AttrState].([]string)[0]
	}

	t.Run("activate, deactivate, destroy", func(t *testing.T) {
		uid := h.create("alice", nil)
		require.Equal(t, StatePreActive, state(uid))

		h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
		require.Equal(t, StateActive, state(uid))
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "activate/"+uid, nil)

		// An active object cannot be destroyed directly.
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "destroy/"+uid, nil)

		h.ok("alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{"reason_code": "superseded", "message": "rotated"})
		require.Equal(t, StateDeactivated, state(uid))
		attrs := h.ok("alice", logical.ReadOperation, "attributes/"+uid, nil).Data["attributes"].(map[string]any)
		require.Equal(t, []string{"superseded", "rotated"}, attrs[AttrRevocationReason])
		require.Contains(t, attrs, AttrDeactivationDate)

		// A deactivated key can still be retrieved until destroyed.
		h.ok("alice", logical.ReadOperation, "get/"+uid, nil)

		h.ok("alice", logical.UpdateOperation, "destroy/"+uid, nil)
		require.Equal(t, StateDestroyed, state(uid))
		h.fails(ReasonKeyValueNotPresent, "alice", logical.ReadOperation, "get/"+uid, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "destroy/"+uid, nil)
	})

	t.Run("destroy erases the key material from storage", func(t *testing.T) {
		uid := h.create("alice", nil)
		h.ok("alice", logical.UpdateOperation, "destroy/"+uid, nil)

		entry, err := h.storage.Get(t.Context(), objectPrefix+uid)
		require.NoError(t, err)
		var obj Object
		require.NoError(t, entry.DecodeJSON(&obj))
		require.Nil(t, obj.Key)
		require.Equal(t, StateDestroyed, obj.State)
		require.False(t, obj.DestroyDate.IsZero())
	})

	t.Run("pre-active objects cannot be deactivated", func(t *testing.T) {
		uid := h.create("alice", nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "revoke/"+uid, nil)
	})

	t.Run("key compromise", func(t *testing.T) {
		uid := h.create("alice", nil)
		occurred := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)

		h.ok("alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{
			"reason_code":                ReasonKeyCompromise,
			"compromise_occurrence_date": occurred.Format(time.RFC3339),
		})
		require.Equal(t, StateCompromised, state(uid))
		attrs := h.ok("alice", logical.ReadOperation, "attributes/"+uid, nil).Data["attributes"].(map[string]any)
		require.Equal(t, []string{occurred.Format(time.RFC3339)}, attrs[AttrCompromiseOccurrenceDate])

		// Compromised objects can still be retrieved, and destroyed.
		h.ok("alice", logical.ReadOperation, "get/"+uid, nil)
		h.ok("alice", logical.UpdateOperation, "destroy/"+uid, nil)
		require.Equal(t, StateDestroyedCompromised, state(uid))
	})

	t.Run("unknown reason", func(t *testing.T) {
		uid := h.create("alice", nil)
		h.ok("alice", logical.UpdateOperation, "activate/"+uid, nil)
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "revoke/"+uid, map[string]any{"reason_code": "bored"})
	})
}

func TestAttributes(t *testing.T) {
	h := newHarness(t)
	uid := h.create("alice", map[string]any{"name": "first"})
	path := "attributes/" + uid

	mutate := func(data map[string]any) *logical.Response {
		return h.ok("alice", logical.UpdateOperation, path, data)
	}

	t.Run("multi-valued names", func(t *testing.T) {
		resp := mutate(map[string]any{"action": "add", "name": AttrName, "value": "second"})
		require.Equal(t, []string{"first", "second"}, resp.Data["values"])

		resp = mutate(map[string]any{"action": "modify", "name": AttrName, "value": "renamed", "index": 1})
		require.Equal(t, []string{"first", "renamed"}, resp.Data["values"])

		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, path, map[string]any{"action": "delete", "name": AttrName})
		resp = mutate(map[string]any{"action": "delete", "name": AttrName, "index": 0})
		require.Equal(t, []string{"renamed"}, resp.Data["values"])
	})

	t.Run("single-valued", func(t *testing.T) {
		mutate(map[string]any{"action": "add", "name": AttrDescription, "value": "backup volume"})
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, path, map[string]any{"action": "add", "name": AttrDescription, "value": "again"})
		mutate(map[string]any{"action": "modify", "name": AttrDescription, "value": "backup volume 2"})
		mutate(map[string]any{"action": "delete", "name": AttrDescription})
		attrs := h.ok("alice", logical.ReadOperation, path, nil).Data["attributes"].(map[string]any)
		require.NotContains(t, attrs, AttrDescription)
	})

	t.Run("server-managed attributes are read-only", func(t *testing.T) {
		for _, name := range []string{AttrState, AttrCryptographicLength, AttrUniqueIdentifier, AttrInitialDate} {
			h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, path, map[string]any{"action": "modify", "name": name, "value": "1"})
		}
		h.fails(ReasonFeatureNotSupported, "alice", logical.UpdateOperation, path, map[string]any{"action": "add", "name": "Archive Date", "value": "1"})
		h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, path, map[string]any{"action": "frobnicate", "name": AttrComment, "value": "1"})
	})

	t.Run("destroyed objects are read-only", func(t *testing.T) {
		gone := h.create("alice", nil)
		h.ok("alice", logical.UpdateOperation, "destroy/"+gone, nil)
		h.fails(ReasonIllegalOperation, "alice", logical.UpdateOperation, "attributes/"+gone, map[string]any{"action": "add", "name": AttrComment, "value": "late"})
	})
}

func TestLocate(t *testing.T) {
	h := newHarness(t)

	a := h.create("alice", map[string]any{"name": "db", "length": 128})
	b := h.create("alice", map[string]any{"name": "db", "length": 256})
	c := h.create("alice", map[string]any{"name": "web", "length": 256})
	h.ok("alice", logical.UpdateOperation, "activate/"+b, nil)

	locate := func(data map[string]any) []string {
		resp := h.ok("alice", logical.UpdateOperation, "locate", data)
		uids, _ := resp.Data["uids"].([]string)
		return uids
	}

	require.ElementsMatch(t, []string{a, b, c}, locate(nil))
	require.ElementsMatch(t, []string{a, b}, locate(map[string]any{"filters": []string{"Name=db"}}))
	require.ElementsMatch(t, []string{b}, locate(map[string]any{"filters": []string{"Name=db", "Cryptographic Length=256"}}))
	require.ElementsMatch(t, []string{b}, locate(map[string]any{"filters": []string{"State=active"}}))
	require.ElementsMatch(t, []string{c}, locate(map[string]any{"filters": []string{"Unique Identifier=" + c}}))
	require.Empty(t, locate(map[string]any{"filters": []string{"Name=nothing"}}))

	// A multi-valued attribute matches on any instance.
	h.ok("alice", logical.UpdateOperation, "attributes/"+c, map[string]any{"action": "add", "name": AttrName, "value": "db"})
	require.ElementsMatch(t, []string{a, b, c}, locate(map[string]any{"filters": []string{"Name=db"}}))

	// Paging.
	all := locate(nil)
	require.Len(t, locate(map[string]any{"max_items": 2}), 2)
	require.Equal(t, all[1:], locate(map[string]any{"offset": 1}))
	resp := h.ok("alice", logical.UpdateOperation, "locate", map[string]any{"max_items": 1})
	require.Equal(t, 3, resp.Data["located_items"])

	h.fails(ReasonInvalidField, "alice", logical.UpdateOperation, "locate", map[string]any{"filters": []string{"no-equals-sign"}})
}
