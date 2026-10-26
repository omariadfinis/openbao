// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Managed object states, following the KMIP 1.4 key lifecycle.
const (
	StatePreActive            = "pre-active"
	StateActive               = "active"
	StateDeactivated          = "deactivated"
	StateCompromised          = "compromised"
	StateDestroyed            = "destroyed"
	StateDestroyedCompromised = "destroyed-compromised"
)

// Managed object types.
const (
	TypeSymmetricKey = "symmetric-key"
	TypeSecretData   = "secret-data"
	TypeOpaqueObject = "opaque-object"
	TypePrivateKey   = "private-key"
	TypePublicKey    = "public-key"
)

// Cryptographic algorithms.
const (
	AlgAES        = "aes"
	AlgHMACSHA1   = "hmac-sha1"
	AlgHMACSHA224 = "hmac-sha224"
	AlgHMACSHA256 = "hmac-sha256"
	AlgHMACSHA384 = "hmac-sha384"
	AlgHMACSHA512 = "hmac-sha512"
	AlgRSA        = "rsa"
	AlgECDSA      = "ecdsa"
)

// Revocation reason codes accepted by Revoke.
const ReasonKeyCompromise = "key-compromise"

var revocationReasons = []string{
	"unspecified",
	ReasonKeyCompromise,
	"ca-compromise",
	"affiliation-changed",
	"superseded",
	"cessation-of-operation",
	"privilege-withdrawn",
}

// Link types.
const (
	LinkPublicKey   = "public-key"
	LinkPrivateKey  = "private-key"
	LinkReplacement = "replacement-object"
	LinkReplaced    = "replaced-object"
)

// Machine-readable failure reasons, returned in the ReasonKey of an error
// response so that the KMIP front end can pick a Result Reason.
const (
	ReasonPermissionDenied      = "permission-denied"
	ReasonMissingData           = "missing-data"
	ReasonItemNotFound          = "item-not-found"
	ReasonInvalidField          = "invalid-field"
	ReasonIllegalOperation      = "illegal-operation"
	ReasonFeatureNotSupported   = "feature-not-supported"
	ReasonKeyValueNotPresent    = "key-value-not-present"
	ReasonNotExtractable        = "not-extractable"
	ReasonSensitive             = "sensitive"
	ReasonCryptographicFailure  = "cryptographic-failure"
	ReasonKeyFormatNotSupported = "key-format-not-supported"
)

// Attribute names, as defined by KMIP 1.4. Values are exchanged as strings.
const (
	AttrUniqueIdentifier         = "Unique Identifier"
	AttrObjectType               = "Object Type"
	AttrName                     = "Name"
	AttrObjectGroup              = "Object Group"
	AttrDescription              = "Description"
	AttrComment                  = "Comment"
	AttrCryptographicAlgorithm   = "Cryptographic Algorithm"
	AttrCryptographicLength      = "Cryptographic Length"
	AttrCryptographicUsageMask   = "Cryptographic Usage Mask"
	AttrState                    = "State"
	AttrInitialDate              = "Initial Date"
	AttrActivationDate           = "Activation Date"
	AttrDeactivationDate         = "Deactivation Date"
	AttrDestroyDate              = "Destroy Date"
	AttrCompromiseDate           = "Compromise Date"
	AttrCompromiseOccurrenceDate = "Compromise Occurrence Date"
	AttrLastChangeDate           = "Last Change Date"
	AttrRevocationReason         = "Revocation Reason"
	AttrExtractable              = "Extractable"
	AttrSensitive                = "Sensitive"
	AttrLink                     = "Link"
	AttrOperationPolicyName      = "Operation Policy Name"
)

// Link is a relationship to another managed object.
type Link struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

// Object is a managed cryptographic object.
type Object struct {
	UID   string `json:"uid"`
	Owner string `json:"owner"`

	Type      string `json:"type"`
	Algorithm string `json:"algorithm,omitempty"`
	Length    int    `json:"length,omitempty"`
	UsageMask int32  `json:"usage_mask"`
	State     string `json:"state"`

	// SecretType is the secret data type ("password" or "seed") of a secret
	// data object, or the numeric opaque data type of an opaque object.
	SecretType string `json:"secret_type,omitempty"`

	Names        []string `json:"names,omitempty"`
	ObjectGroups []string `json:"object_groups,omitempty"`
	Description  string   `json:"description,omitempty"`
	Comment      string   `json:"comment,omitempty"`
	Extractable  bool     `json:"extractable"`
	Sensitive    bool     `json:"sensitive"`
	Links        []Link   `json:"links,omitempty"`

	// Custom holds client-defined "x-" and "y-" attributes.
	Custom map[string][]string `json:"custom,omitempty"`

	InitialDate              time.Time `json:"initial_date"`
	ActivationDate           time.Time `json:"activation_date,omitzero"`
	DeactivationDate         time.Time `json:"deactivation_date,omitzero"`
	DestroyDate              time.Time `json:"destroy_date,omitzero"`
	CompromiseDate           time.Time `json:"compromise_date,omitzero"`
	CompromiseOccurrenceDate time.Time `json:"compromise_occurrence_date,omitzero"`
	LastChangeDate           time.Time `json:"last_change_date"`

	RevocationCode    string `json:"revocation_code,omitempty"`
	RevocationMessage string `json:"revocation_message,omitempty"`

	// Key is the key material: raw bytes for symmetric keys, secret data and
	// opaque objects, a PKCS #8 private key or an X.509 SubjectPublicKeyInfo
	// for asymmetric keys. It is cleared when the object is destroyed; the
	// rest of the object remains as a tombstone.
	Key []byte `json:"key,omitempty"`
}

// opError is a failure with a machine-readable reason.
type opError struct {
	reason string
	msg    string
}

func (e *opError) Error() string { return e.msg }

func failf(reason, format string, args ...any) *opError {
	return &opError{reason: reason, msg: fmt.Sprintf(format, args...)}
}

func isCustom(name string) bool {
	return strings.HasPrefix(name, "x-") || strings.HasPrefix(name, "y-")
}

// Attributes returns every attribute that has a value, as ordered string
// values keyed by KMIP attribute name.
func (o *Object) Attributes() map[string][]string {
	attrs := map[string][]string{
		AttrUniqueIdentifier:       {o.UID},
		AttrObjectType:             {o.Type},
		AttrCryptographicUsageMask: {strconv.Itoa(int(o.UsageMask))},
		AttrState:                  {o.State},
		AttrExtractable:            {strconv.FormatBool(o.Extractable)},
		AttrSensitive:              {strconv.FormatBool(o.Sensitive)},
		AttrInitialDate:            {formatTime(o.InitialDate)},
		AttrLastChangeDate:         {formatTime(o.LastChangeDate)},
	}

	if o.Algorithm != "" {
		attrs[AttrCryptographicAlgorithm] = []string{o.Algorithm}
	}
	if o.Length > 0 {
		attrs[AttrCryptographicLength] = []string{strconv.Itoa(o.Length)}
	}
	if len(o.Names) > 0 {
		attrs[AttrName] = slices.Clone(o.Names)
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
	for _, l := range o.Links {
		attrs[AttrLink] = append(attrs[AttrLink], l.Type+":"+l.UID)
	}
	for name, values := range o.Custom {
		if len(values) > 0 {
			attrs[name] = slices.Clone(values)
		}
	}

	dates := map[string]time.Time{
		AttrActivationDate:           o.ActivationDate,
		AttrDeactivationDate:         o.DeactivationDate,
		AttrDestroyDate:              o.DestroyDate,
		AttrCompromiseDate:           o.CompromiseDate,
		AttrCompromiseOccurrenceDate: o.CompromiseOccurrenceDate,
	}
	for name, t := range dates {
		if !t.IsZero() {
			attrs[name] = []string{formatTime(t)}
		}
	}

	if o.RevocationCode != "" {
		reason := []string{o.RevocationCode}
		if o.RevocationMessage != "" {
			reason = append(reason, o.RevocationMessage)
		}
		attrs[AttrRevocationReason] = reason
	}

	return attrs
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// Matches reports whether the object has every one of the given attribute
// values. A multi-valued attribute matches when any instance equals the
// value.
func (o *Object) Matches(filters map[string][]string) bool {
	attrs := o.Attributes()
	for name, wanted := range filters {
		have := attrs[name]
		for _, w := range wanted {
			if !slices.Contains(have, w) {
				return false
			}
		}
	}
	return true
}

// IsKey reports whether the object holds a cryptographic key.
func (o *Object) IsKey() bool {
	switch o.Type {
	case TypeSymmetricKey, TypePrivateKey, TypePublicKey:
		return true
	}
	return false
}

// Activate moves a Pre-Active object to Active.
func (o *Object) Activate(now time.Time) error {
	if o.State != StatePreActive {
		return failf(ReasonIllegalOperation, "object is %s; only a pre-active object can be activated", o.State)
	}
	o.State = StateActive
	o.ActivationDate = now
	o.LastChangeDate = now
	return nil
}

// Revoke deactivates an Active object, or marks an object compromised when
// the reason is key compromise. occurrence is the time of the compromise and
// is only used for key compromise.
func (o *Object) Revoke(now time.Time, code, message string, occurrence time.Time) error {
	if !slices.Contains(revocationReasons, code) {
		return failf(ReasonInvalidField, "unknown revocation reason %q", code)
	}

	if code == ReasonKeyCompromise {
		switch o.State {
		case StatePreActive, StateActive, StateDeactivated:
		default:
			return failf(ReasonIllegalOperation, "object is %s and cannot be marked compromised", o.State)
		}
		if occurrence.IsZero() {
			occurrence = now
		}
		o.State = StateCompromised
		o.CompromiseDate = now
		o.CompromiseOccurrenceDate = occurrence
	} else {
		if o.State != StateActive {
			return failf(ReasonIllegalOperation, "object is %s; only an active object can be deactivated", o.State)
		}
		o.State = StateDeactivated
		o.DeactivationDate = now
	}

	o.RevocationCode = code
	o.RevocationMessage = message
	o.LastChangeDate = now
	return nil
}

// Destroy removes the key material and moves the object to Destroyed, or
// Destroyed Compromised if it was compromised. An Active object must be
// revoked first.
func (o *Object) Destroy(now time.Time) error {
	switch o.State {
	case StatePreActive, StateDeactivated:
		o.State = StateDestroyed
	case StateCompromised:
		o.State = StateDestroyedCompromised
	case StateActive:
		return failf(ReasonIllegalOperation, "object is active; revoke it before destroying it")
	default:
		return failf(ReasonIllegalOperation, "object is already %s", o.State)
	}

	clear(o.Key)
	o.Key = nil
	o.DestroyDate = now
	o.LastChangeDate = now
	return nil
}

// Destroyed reports whether the key material is gone.
func (o *Object) Destroyed() bool {
	return o.State == StateDestroyed || o.State == StateDestroyedCompromised
}

// multiValued reports whether an attribute may hold several instances,
// addressed by index.
func multiValued(name string) bool {
	return name == AttrName || name == AttrObjectGroup || isCustom(name)
}

// readOnly reports whether the server alone manages an attribute.
func readOnly(name string) bool {
	switch name {
	case AttrUniqueIdentifier, AttrObjectType, AttrCryptographicAlgorithm, AttrCryptographicLength,
		AttrState, AttrInitialDate, AttrActivationDate, AttrDeactivationDate, AttrDestroyDate,
		AttrCompromiseDate, AttrCompromiseOccurrenceDate, AttrLastChangeDate, AttrRevocationReason,
		AttrExtractable, AttrLink:
		return true
	}
	return false
}

// Mutate adds, modifies or deletes a client-settable attribute. index is the
// instance to modify or delete (-1 when the client gave none) and is ignored
// by add. It returns the resulting values of the attribute.
func (o *Object) Mutate(now time.Time, action, name, value string, index int) ([]string, error) {
	if o.Destroyed() {
		return nil, failf(ReasonIllegalOperation, "object is %s; its attributes are read-only", o.State)
	}

	switch {
	case readOnly(name):
		return nil, failf(ReasonIllegalOperation, "attribute %q is read-only", name)
	case isCustom(name):
	default:
		switch name {
		case AttrName, AttrObjectGroup, AttrDescription, AttrComment, AttrCryptographicUsageMask, AttrSensitive:
		default:
			return nil, failf(ReasonFeatureNotSupported, "attribute %q is not supported", name)
		}
	}

	switch action {
	case "add", "modify":
		if value == "" {
			return nil, failf(ReasonInvalidField, "attribute value is required")
		}
	case "delete":
	default:
		return nil, failf(ReasonInvalidField, "unknown action %q", action)
	}

	if multiValued(name) {
		if err := o.mutateMulti(action, name, value, index); err != nil {
			return nil, err
		}
	} else if err := o.mutateSingle(action, name, value); err != nil {
		return nil, err
	}

	o.LastChangeDate = now
	return o.Attributes()[name], nil
}

func (o *Object) multi(name string) *[]string {
	switch name {
	case AttrName:
		return &o.Names
	case AttrObjectGroup:
		return &o.ObjectGroups
	}
	if o.Custom == nil {
		o.Custom = make(map[string][]string)
	}
	values := o.Custom[name]
	return &values
}

func (o *Object) mutateMulti(action, name, value string, index int) error {
	list := o.multi(name)
	defer func() {
		if isCustom(name) {
			if len(*list) == 0 {
				delete(o.Custom, name)
			} else {
				o.Custom[name] = *list
			}
		}
	}()

	if action == "add" {
		*list = append(*list, value)
		return nil
	}

	if index < 0 {
		if len(*list) != 1 {
			return failf(ReasonInvalidField, "attribute %q has %d instances; an index is required", name, len(*list))
		}
		index = 0
	}
	if index >= len(*list) {
		return failf(ReasonInvalidField, "attribute %q has no instance at index %d", name, index)
	}

	if action == "modify" {
		(*list)[index] = value
	} else {
		*list = slices.Delete(*list, index, index+1)
	}
	return nil
}

func (o *Object) mutateSingle(action, name, value string) error {
	isSet := len(o.Attributes()[name]) > 0
	if action == "add" && isSet && name != AttrSensitive && name != AttrCryptographicUsageMask {
		return failf(ReasonIllegalOperation, "attribute %q is single-valued and already set", name)
	}
	if action == "modify" && !isSet {
		return failf(ReasonItemNotFound, "attribute %q is not set", name)
	}
	if action == "delete" {
		switch name {
		case AttrDescription:
			o.Description = ""
		case AttrComment:
			o.Comment = ""
		default:
			return failf(ReasonIllegalOperation, "attribute %q cannot be deleted", name)
		}
		return nil
	}

	switch name {
	case AttrDescription:
		o.Description = value
	case AttrComment:
		o.Comment = value
	case AttrCryptographicUsageMask:
		mask, err := strconv.ParseInt(value, 10, 32)
		if err != nil || mask < 0 {
			return failf(ReasonInvalidField, "invalid usage mask %q", value)
		}
		o.UsageMask = int32(mask)
	case AttrSensitive:
		sensitive, err := strconv.ParseBool(value)
		if err != nil {
			return failf(ReasonInvalidField, "invalid boolean %q", value)
		}
		if o.Sensitive && !sensitive {
			return failf(ReasonIllegalOperation, "a sensitive object cannot be made non-sensitive")
		}
		o.Sensitive = sensitive
	}
	return nil
}

// ApplyAttributes sets the client-supplied attributes of a new object.
// Algorithm, length and object type are checked by the caller against the key
// material; they are accepted here so that a template may carry them.
func (o *Object) ApplyAttributes(now time.Time, attrs map[string][]string) error {
	single := func(name string, values []string) (string, error) {
		if len(values) != 1 {
			return "", failf(ReasonInvalidField, "attribute %q takes exactly one value", name)
		}
		return values[0], nil
	}

	for name, values := range attrs {
		if len(values) == 0 {
			return failf(ReasonInvalidField, "attribute %q has no value", name)
		}

		switch name {
		case AttrName:
			o.Names = slices.Clone(values)
		case AttrObjectGroup:
			o.ObjectGroups = slices.Clone(values)
		case AttrDescription, AttrComment:
			v, err := single(name, values)
			if err != nil {
				return err
			}
			if name == AttrDescription {
				o.Description = v
			} else {
				o.Comment = v
			}
		case AttrCryptographicUsageMask:
			v, err := single(name, values)
			if err != nil {
				return err
			}
			mask, perr := strconv.ParseInt(v, 10, 32)
			if perr != nil || mask < 0 {
				return failf(ReasonInvalidField, "invalid usage mask %q", v)
			}
			o.UsageMask = int32(mask)
		case AttrExtractable, AttrSensitive:
			v, err := single(name, values)
			if err != nil {
				return err
			}
			b, perr := strconv.ParseBool(v)
			if perr != nil {
				return failf(ReasonInvalidField, "invalid boolean %q for %q", v, name)
			}
			if name == AttrExtractable {
				o.Extractable = b
			} else {
				o.Sensitive = b
			}
		case AttrActivationDate:
			v, err := single(name, values)
			if err != nil {
				return err
			}
			t, perr := time.Parse(time.RFC3339, v)
			if perr != nil {
				return failf(ReasonInvalidField, "invalid activation date %q", v)
			}
			o.ActivationDate = t
			if !t.After(now) {
				o.State = StateActive
			}
		case AttrCryptographicAlgorithm, AttrCryptographicLength, AttrObjectType, AttrOperationPolicyName:
			// Checked by the caller, or deprecated and ignored.
		default:
			if !isCustom(name) {
				return failf(ReasonFeatureNotSupported, "attribute %q cannot be set on a new object", name)
			}
			if o.Custom == nil {
				o.Custom = make(map[string][]string)
			}
			o.Custom[name] = slices.Clone(values)
		}
	}
	return nil
}
