// Package kmip is a proof-of-concept KMIP 1.4 front end for OpenBao. It uses
// github.com/ovh/kmip-go for TTLV encoding and message framing and routes
// KMIP operations to handlers. Phase 1 implements Discover Versions and Query.
package kmip

import (
	"slices"
	"sync"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// VendorIdentification is returned for the Query Server Information function.
const VendorIdentification = "OpenBao"

// Handler is a kmipserver.RequestHandler that tracks which operations have
// been registered so that Query can report them.
type Handler struct {
	*kmipserver.BatchExecutor

	mu          sync.RWMutex
	ops         []kmip.Operation
	objectTypes []kmip.ObjectType
}

// NewHandler returns a Handler with the Phase 1 operations registered.
// Discover Versions is answered by the batch executor itself.
func NewHandler() *Handler {
	// Supported versions are deliberately left at the executor's default
	// (1.4 down to 1.0). SetSupportedProtocolVersions sorts ascending, which
	// makes Discover Versions answer with 1.0 first, and clients pick the
	// first entry, so they would negotiate down to 1.0.
	h := &Handler{BatchExecutor: kmipserver.NewBatchExecutor()}

	h.record(kmip.OperationDiscoverVersions)
	h.Route(kmip.OperationQuery, kmipserver.HandleFunc(h.handleQuery))
	h.record(kmip.OperationQuery)

	return h
}

// Handle registers an operation handler and advertises it through Query.
func (h *Handler) Handle(op kmip.Operation, hdl kmipserver.OperationHandler) {
	h.Route(op, hdl)
	h.record(op)
}

func (h *Handler) record(op kmip.Operation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !slices.Contains(h.ops, op) {
		h.ops = append(h.ops, op)
	}
}

// Operations returns the operations this server supports.
func (h *Handler) Operations() []kmip.Operation {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return slices.Clone(h.ops)
}

// AddObjectType advertises a managed object type through Query.
func (h *Handler) AddObjectType(t kmip.ObjectType) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !slices.Contains(h.objectTypes, t) {
		h.objectTypes = append(h.objectTypes, t)
	}
}

// ObjectTypes returns the managed object types this server supports.
func (h *Handler) ObjectTypes() []kmip.ObjectType {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return slices.Clone(h.objectTypes)
}
