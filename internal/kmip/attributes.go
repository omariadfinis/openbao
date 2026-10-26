package kmip

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"

	engine "github.com/openbao/openbao/v2/internal/builtin/logical/kmip"
)

// The engine exchanges every attribute as strings keyed by KMIP attribute
// name. These tables and functions convert between those strings and the
// typed values KMIP carries.

var stateTokens = map[kmip.State]string{
	kmip.StatePreActive:            engine.StatePreActive,
	kmip.StateActive:               engine.StateActive,
	kmip.StateDeactivated:          engine.StateDeactivated,
	kmip.StateCompromised:          engine.StateCompromised,
	kmip.StateDestroyed:            engine.StateDestroyed,
	kmip.StateDestroyedCompromised: engine.StateDestroyedCompromised,
}

var reasonTokens = map[kmip.RevocationReasonCode]string{
	kmip.RevocationReasonCodeUnspecified:          "unspecified",
	kmip.RevocationReasonCodeKeyCompromise:        engine.ReasonKeyCompromise,
	kmip.RevocationReasonCodeCACompromise:         "ca-compromise",
	kmip.RevocationReasonCodeAffiliationChanged:   "affiliation-changed",
	kmip.RevocationReasonCodeSuperseded:           "superseded",
	kmip.RevocationReasonCodeCessationOfOperation: "cessation-of-operation",
	kmip.RevocationReasonCodePrivilegeWithdrawn:   "privilege-withdrawn",
}

var algorithmTokens = map[kmip.CryptographicAlgorithm]string{
	kmip.CryptographicAlgorithmAES:        engine.AlgAES,
	kmip.CryptographicAlgorithmRSA:        engine.AlgRSA,
	kmip.CryptographicAlgorithmECDSA:      engine.AlgECDSA,
	kmip.CryptographicAlgorithmHMACSHA1:   engine.AlgHMACSHA1,
	kmip.CryptographicAlgorithmHMACSHA224: engine.AlgHMACSHA224,
	kmip.CryptographicAlgorithmHMACSHA256: engine.AlgHMACSHA256,
	kmip.CryptographicAlgorithmHMACSHA384: engine.AlgHMACSHA384,
	kmip.CryptographicAlgorithmHMACSHA512: engine.AlgHMACSHA512,
}

var objectTypeTokens = map[kmip.ObjectType]string{
	kmip.ObjectTypeSymmetricKey: engine.TypeSymmetricKey,
	kmip.ObjectTypeSecretData:   engine.TypeSecretData,
	kmip.ObjectTypeOpaqueObject: engine.TypeOpaqueObject,
	kmip.ObjectTypePrivateKey:   engine.TypePrivateKey,
	kmip.ObjectTypePublicKey:    engine.TypePublicKey,
}

var linkTokens = map[kmip.LinkType]string{
	kmip.LinkTypePublicKeyLink:         engine.LinkPublicKey,
	kmip.LinkTypePrivateKeyLink:        engine.LinkPrivateKey,
	kmip.LinkTypeReplacementObjectLink: engine.LinkReplacement,
	kmip.LinkTypeReplacedObjectLink:    engine.LinkReplaced,
}

func invert[K comparable](m map[K]string) map[string]K {
	out := make(map[string]K, len(m))
	for k, v := range m {
		out[v] = k
	}
	return out
}

var (
	stateByToken     = invert(stateTokens)
	reasonByToken    = invert(reasonTokens)
	algorithmByToken = invert(algorithmTokens)
	objectTypeByTok  = invert(objectTypeTokens)
	linkByToken      = invert(linkTokens)
)

func errField(format string, args ...any) error {
	return kmipserver.Errorf(kmip.ResultReasonInvalidField, format, args...)
}

func notSupported(format string, args ...any) error {
	return kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, format, args...)
}

// attributeValueString converts the value of a KMIP attribute to the string
// the engine stores and compares.
func attributeValueString(name kmip.AttributeName, value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case int32:
		return strconv.Itoa(int(v)), nil
	case time.Time:
		return v.UTC().Format(time.RFC3339), nil
	case kmip.Name:
		if v.NameType != 0 && v.NameType != kmip.NameTypeUninterpretedTextString {
			return "", notSupported("name type %v is not supported", v.NameType)
		}
		return v.NameValue, nil
	case kmip.CryptographicUsageMask:
		return strconv.Itoa(int(v)), nil
	case kmip.CryptographicAlgorithm:
		token, ok := algorithmTokens[v]
		if !ok {
			return "", notSupported("cryptographic algorithm %v is not supported", v)
		}
		return token, nil
	case kmip.ObjectType:
		token, ok := objectTypeTokens[v]
		if !ok {
			return "", notSupported("object type %v is not supported", v)
		}
		return token, nil
	case kmip.State:
		token, ok := stateTokens[v]
		if !ok {
			return "", errField("unknown state %v", v)
		}
		return token, nil
	case kmip.Link:
		token, ok := linkTokens[v.LinkType]
		if !ok {
			return "", notSupported("link type %v is not supported", v.LinkType)
		}
		return token + ":" + v.LinkedObjectIdentifier, nil
	case ttlv.Value:
		// Only client-defined attributes arrive as raw TTLV values, and
		// only text values are kept.
		if text, ok := v.Value.(string); ok && isCustomAttribute(name) {
			return text, nil
		}
	case *ttlv.Value:
		if v != nil {
			return attributeValueString(name, *v)
		}
	}
	return "", notSupported("attribute %q is not supported or has an unsupported value type %T", name, value)
}

func isCustomAttribute(name kmip.AttributeName) bool {
	return strings.HasPrefix(string(name), "x-") || strings.HasPrefix(string(name), "y-")
}

// attributeFromStrings builds the typed KMIP attribute instances for an
// engine attribute. A multi-valued attribute yields one instance per value,
// each carrying its index.
func attributeFromStrings(name kmip.AttributeName, values []string) ([]kmip.Attribute, error) {
	multi := name == kmip.AttributeNameName || name == kmip.AttributeNameObjectGroup ||
		name == kmip.AttributeNameLink || isCustomAttribute(name)

	attrs := make([]kmip.Attribute, 0, len(values))
	for i, s := range values {
		value, err := typedValue(name, values, s)
		if err != nil {
			return nil, err
		}
		attr := kmip.Attribute{AttributeName: name, AttributeValue: value}
		if multi {
			idx := int32(i)
			attr.AttributeIndex = &idx
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

func typedValue(name kmip.AttributeName, values []string, s string) (any, error) {
	if isCustomAttribute(name) {
		return s, nil
	}

	switch name {
	case kmip.AttributeNameUniqueIdentifier, kmip.AttributeNameObjectGroup,
		kmip.AttributeNameDescription, kmip.AttributeNameComment:
		return s, nil
	case kmip.AttributeNameName:
		return kmip.Name{NameValue: s, NameType: kmip.NameTypeUninterpretedTextString}, nil
	case kmip.AttributeNameObjectType:
		t, ok := objectTypeByTok[s]
		if !ok {
			return nil, fmt.Errorf("unknown object type %q", s)
		}
		return t, nil
	case kmip.AttributeNameCryptographicAlgorithm:
		a, ok := algorithmByToken[s]
		if !ok {
			return nil, fmt.Errorf("unknown algorithm %q", s)
		}
		return a, nil
	case kmip.AttributeNameCryptographicLength:
		n, err := strconv.ParseInt(s, 10, 32)
		return int32(n), err
	case kmip.AttributeNameCryptographicUsageMask:
		n, err := strconv.ParseInt(s, 10, 32)
		return kmip.CryptographicUsageMask(n), err
	case kmip.AttributeNameState:
		state, ok := stateByToken[s]
		if !ok {
			return nil, fmt.Errorf("unknown state %q", s)
		}
		return state, nil
	case kmip.AttributeNameExtractable, kmip.AttributeNameSensitive:
		return strconv.ParseBool(s)
	case kmip.AttributeNameInitialDate, kmip.AttributeNameActivationDate, kmip.AttributeNameDeactivationDate,
		kmip.AttributeNameDestroyDate, kmip.AttributeNameCompromiseDate,
		kmip.AttributeNameCompromiseOccurrenceDate, kmip.AttributeNameLastChangeDate:
		return time.Parse(time.RFC3339, s)
	case kmip.AttributeNameLink:
		typ, uid, ok := strings.Cut(s, ":")
		lt, known := linkByToken[typ]
		if !ok || !known {
			return nil, fmt.Errorf("malformed link %q", s)
		}
		return kmip.Link{LinkType: lt, LinkedObjectIdentifier: uid}, nil
	case kmip.AttributeNameRevocationReason:
		// The engine returns the reason code, then optionally the message.
		code, ok := reasonByToken[values[0]]
		if !ok {
			return nil, fmt.Errorf("unknown revocation reason %q", values[0])
		}
		reason := kmip.RevocationReason{RevocationReasonCode: code}
		if len(values) > 1 {
			reason.RevocationMessage = values[1]
		}
		return reason, nil
	}
	return nil, fmt.Errorf("unsupported attribute %q", name)
}

// attributesFromEngine converts the engine's attribute map to KMIP
// attributes. When names is not empty only those attributes are returned;
// attributes the object does not have are omitted.
func attributesFromEngine(attrs map[string][]string, names []kmip.AttributeName) ([]kmip.Attribute, error) {
	if len(names) == 0 {
		for name := range attrs {
			names = append(names, kmip.AttributeName(name))
		}
	}
	slices.Sort(names)

	var out []kmip.Attribute
	for _, name := range names {
		values := attrs[string(name)]
		if len(values) == 0 {
			continue
		}

		// A revocation reason is one structured value, not a list.
		if name == kmip.AttributeNameRevocationReason {
			value, err := typedValue(name, values, values[0])
			if err != nil {
				return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
			}
			out = append(out, kmip.Attribute{AttributeName: name, AttributeValue: value})
			continue
		}

		converted, err := attributeFromStrings(name, values)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
		}
		out = append(out, converted...)
	}
	return out, nil
}

// templateAttributes converts the attributes of a template, as sent with
// Create, Register, Create Key Pair and Re-key, to the engine's form.
func templateAttributes(t *kmip.TemplateAttribute) (map[string]any, error) {
	out := make(map[string]any)
	if t == nil {
		return out, nil
	}

	values := make(map[string][]string)
	var curveBits string
	for _, attr := range t.Attribute {
		// Operation Policy Name is deprecated and has no effect here.
		if attr.AttributeName == kmip.AttributeNameOperationPolicyName {
			continue
		}
		// An elliptic curve is named by its domain parameters; the engine
		// takes it as the key length.
		if attr.AttributeName == kmip.AttributeNameCryptographicDomainParameters {
			params, ok := attr.AttributeValue.(kmip.CryptographicDomainParameters)
			if !ok {
				return nil, notSupported("unsupported cryptographic domain parameters")
			}
			bits, ok := curveLengths[params.RecommendedCurve]
			if !ok {
				return nil, notSupported("curve %v is not supported; use P-256, P-384 or P-521", params.RecommendedCurve)
			}
			curveBits = bits
			continue
		}
		value, err := attributeValueString(attr.AttributeName, attr.AttributeValue)
		if err != nil {
			return nil, err
		}
		values[string(attr.AttributeName)] = append(values[string(attr.AttributeName)], value)
	}
	if curveBits != "" {
		if given := values[string(kmip.AttributeNameCryptographicLength)]; len(given) > 0 && given[0] != curveBits {
			return nil, errField("cryptographic length %s does not match the %s-bit curve", given[0], curveBits)
		}
		values[string(kmip.AttributeNameCryptographicLength)] = []string{curveBits}
	}
	for name, v := range values {
		out[name] = v
	}
	return out, nil
}

// curveLengths maps the recommended curves this server supports to the key
// length in bits the engine expects.
var curveLengths = map[kmip.RecommendedCurve]string{
	kmip.RecommendedCurveP_256: "256",
	kmip.RecommendedCurveP_384: "384",
	kmip.RecommendedCurveP_521: "521",
}

// mergeAttributes overlays over onto base without modifying either.
func mergeAttributes(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
