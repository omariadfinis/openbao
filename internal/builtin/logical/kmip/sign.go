// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256" // register SHA-224 and SHA-256
	_ "crypto/sha512" // register SHA-384 and SHA-512
	"crypto/x509"
	"strings"
)

// Padding schemes for RSA signatures.
const (
	PaddingPKCS1v15 = "pkcs1v15"
	PaddingPSS      = "pss"
)

// hashFor maps a hash name to its implementation. SHA-1 and MD5 are not
// offered for signing or MACs.
func hashFor(name string) (crypto.Hash, error) {
	switch strings.ToLower(name) {
	case "sha224":
		return crypto.SHA224, nil
	case "sha256", "":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	}
	return 0, failf(ReasonFeatureNotSupported, "hash algorithm %q is not supported", name)
}

// digest returns the digest to sign or verify: data itself when it is
// already a digest, otherwise its hash.
func digest(h crypto.Hash, data []byte, prehashed bool) ([]byte, error) {
	if prehashed {
		if len(data) != h.Size() {
			return nil, failf(ReasonInvalidField, "digest is %d bytes; %s needs %d", len(data), h, h.Size())
		}
		return data, nil
	}
	hash := h.New()
	hash.Write(data)
	return hash.Sum(nil), nil
}

func (o *Object) signer() (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(o.Key)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, failf(ReasonIllegalOperation, "key cannot sign")
	}
	return signer, nil
}

// SignParams selects how a signature is made or checked.
type SignParams struct {
	Hash       string
	Padding    string
	SaltLength int // PSS only; 0 selects the hash length
	Prehashed  bool
}

func (p SignParams) pssOptions(h crypto.Hash) *rsa.PSSOptions {
	salt := p.SaltLength
	if salt <= 0 {
		salt = rsa.PSSSaltLengthEqualsHash
	}
	return &rsa.PSSOptions{SaltLength: salt, Hash: h}
}

// Sign signs data with a private key. ECDSA signatures are ASN.1 DER
// encoded.
func (o *Object) Sign(data []byte, p SignParams) ([]byte, error) {
	if o.Type != TypePrivateKey {
		return nil, failf(ReasonIllegalOperation, "object is not a private key")
	}
	if err := o.checkUsable(UsageSign, StateActive); err != nil {
		return nil, err
	}
	h, err := hashFor(p.Hash)
	if err != nil {
		return nil, err
	}
	sum, err := digest(h, data, p.Prehashed)
	if err != nil {
		return nil, err
	}
	signer, err := o.signer()
	if err != nil {
		return nil, err
	}

	switch o.Algorithm {
	case AlgRSA:
		switch p.Padding {
		case PaddingPSS:
			return signer.Sign(rand.Reader, sum, p.pssOptions(h))
		case PaddingPKCS1v15, "":
			return signer.Sign(rand.Reader, sum, h)
		}
		return nil, failf(ReasonFeatureNotSupported, "padding %q is not supported", p.Padding)
	case AlgECDSA:
		return signer.Sign(rand.Reader, sum, h)
	}
	return nil, failf(ReasonFeatureNotSupported, "algorithm %q cannot sign", o.Algorithm)
}

// Verify checks a signature with a public key. A signature that does not
// match is reported as false, not as an error.
func (o *Object) Verify(data, signature []byte, p SignParams) (bool, error) {
	if o.Type != TypePublicKey {
		return false, failf(ReasonIllegalOperation, "object is not a public key")
	}
	if err := o.checkUsable(UsageVerify, StateActive, StateDeactivated, StateCompromised); err != nil {
		return false, err
	}
	h, err := hashFor(p.Hash)
	if err != nil {
		return false, err
	}
	sum, err := digest(h, data, p.Prehashed)
	if err != nil {
		return false, err
	}
	key, err := x509.ParsePKIXPublicKey(o.Key)
	if err != nil {
		return false, err
	}

	switch pub := key.(type) {
	case *rsa.PublicKey:
		switch p.Padding {
		case PaddingPSS:
			return rsa.VerifyPSS(pub, h, sum, signature, p.pssOptions(h)) == nil, nil
		case PaddingPKCS1v15, "":
			return rsa.VerifyPKCS1v15(pub, h, sum, signature) == nil, nil
		}
		return false, failf(ReasonFeatureNotSupported, "padding %q is not supported", p.Padding)
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, sum, signature), nil
	}
	return false, failf(ReasonFeatureNotSupported, "algorithm %q cannot verify", o.Algorithm)
}

func (o *Object) macHash(name string) (crypto.Hash, error) {
	if o.Type != TypeSymmetricKey || !isHMAC(o.Algorithm) {
		return 0, failf(ReasonIllegalOperation, "object is not an HMAC key")
	}
	keyHash := strings.TrimPrefix(o.Algorithm, "hmac-")
	if name != "" && !strings.EqualFold(name, keyHash) {
		return 0, failf(ReasonInvalidField, "key is for %s but %s was requested", o.Algorithm, name)
	}
	if keyHash == "sha1" {
		return crypto.SHA1, nil
	}
	return hashFor(keyHash)
}

// MAC computes the HMAC of data. name optionally names the hash, which must
// then match the key's algorithm.
func (o *Object) MAC(data []byte, name string) ([]byte, error) {
	h, err := o.macHash(name)
	if err != nil {
		return nil, err
	}
	if err := o.checkUsable(UsageMACGenerate, StateActive); err != nil {
		return nil, err
	}
	mac := hmac.New(h.New, o.Key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyMAC checks an HMAC in constant time.
func (o *Object) VerifyMAC(data, expected []byte, name string) (bool, error) {
	h, err := o.macHash(name)
	if err != nil {
		return false, err
	}
	if err := o.checkUsable(UsageMACVerify, StateActive, StateDeactivated, StateCompromised); err != nil {
		return false, err
	}
	mac := hmac.New(h.New, o.Key)
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), expected), nil
}
