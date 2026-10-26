// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"strings"
)

// Key formats accepted by Register and returned by Get.
const (
	FormatRaw          = "raw"
	FormatOpaque       = "opaque"
	FormatPKCS1        = "pkcs1"
	FormatPKCS8        = "pkcs8"
	FormatX509         = "x509"
	FormatECPrivateKey = "ec-private-key"
)

var aesLengths = []int{128, 192, 256}

const (
	minHMACBits = 128
	maxHMACBits = 1024
)

// isHMAC reports whether an algorithm is one of the HMAC variants.
func isHMAC(alg string) bool {
	return strings.HasPrefix(alg, "hmac-")
}

// validateSymmetric checks an algorithm and key length in bits.
func validateSymmetric(alg string, bits int) error {
	switch {
	case alg == AlgAES:
		if !slices.Contains(aesLengths, bits) {
			return failf(ReasonInvalidField, "invalid AES key length %d", bits)
		}
	case isHMAC(alg):
		switch alg {
		case AlgHMACSHA1, AlgHMACSHA224, AlgHMACSHA256, AlgHMACSHA384, AlgHMACSHA512:
		default:
			return failf(ReasonFeatureNotSupported, "algorithm %q is not supported", alg)
		}
		if bits < minHMACBits || bits > maxHMACBits || bits%8 != 0 {
			return failf(ReasonInvalidField, "invalid HMAC key length %d; use a multiple of 8 from %d to %d", bits, minHMACBits, maxHMACBits)
		}
	default:
		return failf(ReasonFeatureNotSupported, "algorithm %q is not supported for symmetric keys", alg)
	}
	return nil
}

// generateSymmetric returns random key material of the given length.
func generateSymmetric(alg string, bits int) ([]byte, error) {
	if err := validateSymmetric(alg, bits); err != nil {
		return nil, err
	}
	key := make([]byte, bits/8)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func curveFor(bits int) (elliptic.Curve, error) {
	switch bits {
	case 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	}
	return nil, failf(ReasonInvalidField, "invalid ECDSA key length %d; use 256, 384 or 521", bits)
}

// generateKeyPair returns a PKCS #8 private key and an X.509
// SubjectPublicKeyInfo public key.
func generateKeyPair(alg string, bits int) (private, public []byte, err error) {
	switch alg {
	case AlgRSA:
		if !slices.Contains([]int{2048, 3072, 4096}, bits) {
			return nil, nil, failf(ReasonInvalidField, "invalid RSA key length %d; use 2048, 3072 or 4096", bits)
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return marshalPair(k, &k.PublicKey)
	case AlgECDSA:
		curve, err := curveFor(bits)
		if err != nil {
			return nil, nil, err
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return marshalPair(k, &k.PublicKey)
	}
	return nil, nil, failf(ReasonFeatureNotSupported, "algorithm %q is not supported for key pairs", alg)
}

func marshalPair(priv, pub any) (private, public []byte, err error) {
	if private, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
		return nil, nil, err
	}
	if public, err = x509.MarshalPKIXPublicKey(pub); err != nil {
		return nil, nil, err
	}
	return private, public, nil
}

// describeKey reports the algorithm and length of a parsed asymmetric key.
func describeKey(key any) (alg string, bits int, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return AlgRSA, k.N.BitLen(), nil
	case *rsa.PublicKey:
		return AlgRSA, k.N.BitLen(), nil
	case *ecdsa.PrivateKey:
		return AlgECDSA, k.Curve.Params().BitSize, nil
	case *ecdsa.PublicKey:
		return AlgECDSA, k.Curve.Params().BitSize, nil
	}
	return "", 0, failf(ReasonFeatureNotSupported, "key type %T is not supported", key)
}

// parseRegistered validates key material supplied to Register for the given
// object type and returns its normalised form: raw bytes, PKCS #8 for private
// keys, or SubjectPublicKeyInfo for public keys. alg and bits are the values
// the client declared, if any; the returned values are authoritative.
func parseRegistered(typ string, material []byte, format, alg string, bits int) (outAlg string, outBits int, out []byte, err error) {
	if len(material) == 0 {
		return "", 0, nil, failf(ReasonMissingData, "key material is required")
	}

	switch typ {
	case TypeSymmetricKey:
		if format != "" && format != FormatRaw {
			return "", 0, nil, failf(ReasonKeyFormatNotSupported, "symmetric keys are registered in the raw format")
		}
		if alg == "" {
			alg = AlgAES
		}
		if bits != 0 && bits != len(material)*8 {
			return "", 0, nil, failf(ReasonInvalidField, "declared length %d does not match the %d-bit key material", bits, len(material)*8)
		}
		if err := validateSymmetric(alg, len(material)*8); err != nil {
			return "", 0, nil, err
		}
		return alg, len(material) * 8, slices.Clone(material), nil

	case TypeSecretData, TypeOpaqueObject:
		if format != "" && format != FormatRaw && format != FormatOpaque {
			return "", 0, nil, failf(ReasonKeyFormatNotSupported, "%s objects are registered as raw bytes", typ)
		}
		return "", 0, slices.Clone(material), nil

	case TypePrivateKey:
		var key any
		switch format {
		case FormatPKCS8, "":
			key, err = x509.ParsePKCS8PrivateKey(material)
		case FormatPKCS1:
			key, err = x509.ParsePKCS1PrivateKey(material)
		case FormatECPrivateKey:
			key, err = x509.ParseECPrivateKey(material)
		default:
			return "", 0, nil, failf(ReasonKeyFormatNotSupported, "private key format %q is not supported", format)
		}
		if err != nil {
			return "", 0, nil, failf(ReasonInvalidField, "invalid private key: %v", err)
		}
		return normalise(key, alg, bits, x509.MarshalPKCS8PrivateKey)

	case TypePublicKey:
		var key any
		switch format {
		case FormatX509, "":
			key, err = x509.ParsePKIXPublicKey(material)
		case FormatPKCS1:
			key, err = x509.ParsePKCS1PublicKey(material)
		default:
			return "", 0, nil, failf(ReasonKeyFormatNotSupported, "public key format %q is not supported", format)
		}
		if err != nil {
			return "", 0, nil, failf(ReasonInvalidField, "invalid public key: %v", err)
		}
		return normalise(key, alg, bits, x509.MarshalPKIXPublicKey)
	}
	return "", 0, nil, failf(ReasonFeatureNotSupported, "object type %q is not supported", typ)
}

func normalise(key any, alg string, bits int, marshal func(any) ([]byte, error)) (string, int, []byte, error) {
	gotAlg, gotBits, err := describeKey(key)
	if err != nil {
		return "", 0, nil, err
	}
	if alg != "" && alg != gotAlg {
		return "", 0, nil, failf(ReasonInvalidField, "declared algorithm %q does not match the %s key", alg, gotAlg)
	}
	if bits != 0 && bits != gotBits {
		return "", 0, nil, failf(ReasonInvalidField, "declared length %d does not match the %d-bit key", bits, gotBits)
	}
	der, err := marshal(key)
	if err != nil {
		return "", 0, nil, err
	}
	return gotAlg, gotBits, der, nil
}

// defaultFormat is the format Get returns when the client names none.
func defaultFormat(typ string) string {
	switch typ {
	case TypePrivateKey:
		return FormatPKCS8
	case TypePublicKey:
		return FormatX509
	}
	return FormatRaw
}

// Export returns the key material in the requested format. An empty format
// selects the default for the object type.
func (o *Object) Export(format string) ([]byte, error) {
	if format == "" {
		format = defaultFormat(o.Type)
	}

	switch o.Type {
	case TypeSymmetricKey:
		if format == FormatRaw {
			return slices.Clone(o.Key), nil
		}
	case TypeSecretData, TypeOpaqueObject:
		if format == FormatRaw || format == FormatOpaque {
			return slices.Clone(o.Key), nil
		}
	case TypePrivateKey:
		switch format {
		case FormatPKCS8:
			return slices.Clone(o.Key), nil
		case FormatPKCS1, FormatECPrivateKey:
			key, err := x509.ParsePKCS8PrivateKey(o.Key)
			if err != nil {
				return nil, err
			}
			if k, ok := key.(*rsa.PrivateKey); ok && format == FormatPKCS1 {
				return x509.MarshalPKCS1PrivateKey(k), nil
			}
			if k, ok := key.(*ecdsa.PrivateKey); ok && format == FormatECPrivateKey {
				return x509.MarshalECPrivateKey(k)
			}
		}
	case TypePublicKey:
		switch format {
		case FormatX509:
			return slices.Clone(o.Key), nil
		case FormatPKCS1:
			key, err := x509.ParsePKIXPublicKey(o.Key)
			if err != nil {
				return nil, err
			}
			if k, ok := key.(*rsa.PublicKey); ok {
				return x509.MarshalPKCS1PublicKey(k), nil
			}
		}
	}
	return nil, failf(ReasonKeyFormatNotSupported, "a %s cannot be returned in the %q format", o.Type, format)
}
