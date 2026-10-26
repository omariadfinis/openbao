// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"slices"
)

// Cryptographic usage mask bits, as defined by KMIP 1.4 section 3.19.
const (
	UsageSign        int32 = 0x00000001
	UsageVerify      int32 = 0x00000002
	UsageEncrypt     int32 = 0x00000004
	UsageDecrypt     int32 = 0x00000008
	UsageMACGenerate int32 = 0x00000080
	UsageMACVerify   int32 = 0x00000100
)

const (
	gcmNonceSize      = 12
	gcmDefaultTagSize = 16
	gcmMinTagSize     = 12
)

// checkUsable verifies that the object may be used for the cryptographic
// operation named by usage. Encrypting needs an Active key; decrypting is
// also allowed once the key is Deactivated or Compromised, so that data
// protected earlier can still be read.
func (o *Object) checkUsable(usage int32, states ...string) error {
	if !slices.Contains(states, o.State) {
		return failf(ReasonIllegalOperation, "object is %s and cannot be used for this operation", o.State)
	}
	if o.UsageMask&usage != usage {
		return failf(ReasonIllegalOperation, "object's cryptographic usage mask does not permit this operation")
	}
	return nil
}

func (o *Object) aead(tagSize int) (cipher.AEAD, error) {
	if tagSize < gcmMinTagSize || tagSize > gcmDefaultTagSize {
		return nil, failf(ReasonInvalidField, "tag length must be between %d and %d bytes", gcmMinTagSize, gcmDefaultTagSize)
	}
	block, err := aes.NewCipher(o.Key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithTagSize(block, tagSize)
}

// Encrypt seals plaintext with AES-GCM under a fresh random nonce. It
// returns the ciphertext, the nonce and the authentication tag separately,
// as KMIP carries them. A tagSize of 0 selects the 16-byte default.
func (o *Object) Encrypt(plaintext, aad []byte, tagSize int) (ciphertext, nonce, tag []byte, err error) {
	if err := o.requireAES(); err != nil {
		return nil, nil, nil, err
	}
	if err := o.checkUsable(UsageEncrypt, StateActive); err != nil {
		return nil, nil, nil, err
	}
	if tagSize == 0 {
		tagSize = gcmDefaultTagSize
	}
	aead, err := o.aead(tagSize)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	split := len(sealed) - tagSize
	return sealed[:split], nonce, sealed[split:], nil
}

// Decrypt opens ciphertext that Encrypt produced. Any failure to
// authenticate, whether from a wrong key, nonce, tag or associated data,
// is reported as a cryptographic failure without further detail.
func (o *Object) Decrypt(ciphertext, nonce, tag, aad []byte) ([]byte, error) {
	if err := o.requireAES(); err != nil {
		return nil, err
	}
	if err := o.checkUsable(UsageDecrypt, StateActive, StateDeactivated, StateCompromised); err != nil {
		return nil, err
	}
	if len(nonce) != gcmNonceSize {
		return nil, failf(ReasonInvalidField, "nonce must be %d bytes", gcmNonceSize)
	}
	aead, err := o.aead(len(tag))
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, append(slices.Clone(ciphertext), tag...), aad)
	if err != nil {
		return nil, failf(ReasonCryptographicFailure, "decryption failed")
	}
	return plaintext, nil
}

func (o *Object) requireAES() error {
	if o.Type != TypeSymmetricKey || o.Algorithm != AlgAES {
		return failf(ReasonIllegalOperation, "object is not an AES key")
	}
	return nil
}
