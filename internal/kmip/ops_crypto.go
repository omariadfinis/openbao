package kmip

import (
	"context"
	"encoding/base64"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// gcmTagBytes validates the cryptographic parameters of an Encrypt or Decrypt
// request, which must describe single-shot AES-GCM, and returns the requested
// authentication tag length in bytes (0 for the default).
//
// Only AES-GCM is offered. Modes without authentication, ECB in particular,
// are refused rather than silently substituted.
func gcmTagBytes(ctx context.Context, params *kmip.CryptographicParameters) (int, error) {
	// The tag and additional authenticated data only exist from KMIP 1.4.
	if v := kmipserver.GetProtocolVersion(ctx); v.ProtocolVersionMajor == 1 && v.ProtocolVersionMinor < 4 {
		return 0, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported,
			"AES-GCM needs KMIP 1.4 to carry the authentication tag; the connection uses %d.%d",
			v.ProtocolVersionMajor, v.ProtocolVersionMinor)
	}
	if params == nil {
		return 0, nil
	}

	switch params.BlockCipherMode {
	case 0, kmip.BlockCipherModeGCM, kmip.BlockCipherModeAEAD:
	default:
		return 0, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported,
			"block cipher mode %v is not supported; only GCM is", params.BlockCipherMode)
	}
	if params.CryptographicAlgorithm != 0 && params.CryptographicAlgorithm != kmip.CryptographicAlgorithmAES {
		return 0, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported,
			"cryptographic algorithm %v is not supported", params.CryptographicAlgorithm)
	}
	if params.PaddingMethod != 0 && params.PaddingMethod != kmip.PaddingMethodNone {
		return 0, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "padding is not used with GCM")
	}
	// The IV Length is in bits.
	if params.IVLength != 0 && params.IVLength != 96 {
		return 0, errField("IV length must be 96 bits")
	}
	// The Tag Length is in bytes.
	return int(params.TagLength), nil
}

// rejectStreaming refuses multi-part requests: the key is used in single
// calls only.
func rejectStreaming(correlation []byte, init, final *bool) error {
	multiPart := len(correlation) > 0 ||
		(init != nil && *init && (final == nil || !*final)) ||
		(final != nil && !*final)
	if multiPart {
		return kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "multi-part encryption is not supported")
	}
	return nil
}

func (o *objectOps) encrypt(ctx context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	tagLen, err := gcmTagBytes(ctx, req.CryptographicParameters)
	if err != nil {
		return nil, err
	}
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	// A GCM nonce must never repeat under one key, so the server always
	// chooses it.
	if len(req.IVCounterNonce) > 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported,
			"client-supplied IVs are not accepted; the server generates and returns the IV")
	}

	data := map[string]any{
		"data": base64.StdEncoding.EncodeToString(req.Data),
		"aad":  base64.StdEncoding.EncodeToString(req.AuthenticatedEncryptionAdditionalData),
	}
	if tagLen > 0 {
		data["tag_length"] = tagLen
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "encrypt/"+uid, data)
	if err != nil {
		return nil, err
	}

	out := &payloads.EncryptResponsePayload{UniqueIdentifier: uid}
	if out.Data, err = decodeEngineBytes(resp, "data"); err != nil {
		return nil, err
	}
	if out.IVCounterNonce, err = decodeEngineBytes(resp, "iv"); err != nil {
		return nil, err
	}
	if out.AuthenticatedEncryptionTag, err = decodeEngineBytes(resp, "tag"); err != nil {
		return nil, err
	}
	return out, nil
}

func (o *objectOps) decrypt(ctx context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if _, err := gcmTagBytes(ctx, req.CryptographicParameters); err != nil {
		return nil, err
	}
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "decrypt/"+uid, map[string]any{
		"data": base64.StdEncoding.EncodeToString(req.Data),
		"iv":   base64.StdEncoding.EncodeToString(req.IVCounterNonce),
		"tag":  base64.StdEncoding.EncodeToString(req.AuthenticatedEncryptionTag),
		"aad":  base64.StdEncoding.EncodeToString(req.AuthenticatedEncryptionAdditionalData),
	})
	if err != nil {
		return nil, err
	}

	out := &payloads.DecryptResponsePayload{UniqueIdentifier: uid}
	if out.Data, err = decodeEngineBytes(resp, "data"); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeEngineBytes(resp *logical.Response, field string) ([]byte, error) {
	raw, _ := resp.Data[field].(string)
	out, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "decoding %s: %v", field, err)
	}
	return out, nil
}

var hashingTokens = map[kmip.HashingAlgorithm]string{
	kmip.HashingAlgorithmSHA_224: "sha224",
	kmip.HashingAlgorithmSHA_256: "sha256",
	kmip.HashingAlgorithmSHA_384: "sha384",
	kmip.HashingAlgorithmSHA_512: "sha512",
}

// signatureAlgorithms maps a KMIP digital signature algorithm to the hash and
// padding it implies. SHA-1, MD2 and MD5 variants are not offered.
var signatureAlgorithms = map[kmip.DigitalSignatureAlgorithm]struct{ hash, padding string }{
	kmip.DigitalSignatureAlgorithmSHA_224WithRSAEncryption: {"sha224", "pkcs1v15"},
	kmip.DigitalSignatureAlgorithmSHA_256WithRSAEncryption: {"sha256", "pkcs1v15"},
	kmip.DigitalSignatureAlgorithmSHA_384WithRSAEncryption: {"sha384", "pkcs1v15"},
	kmip.DigitalSignatureAlgorithmSHA_512WithRSAEncryption: {"sha512", "pkcs1v15"},
	kmip.DigitalSignatureAlgorithmRSASSA_PSS:               {"", "pss"},
	kmip.DigitalSignatureAlgorithmECDSAWithSHA224:          {"sha224", ""},
	kmip.DigitalSignatureAlgorithmECDSAWithSHA256:          {"sha256", ""},
	kmip.DigitalSignatureAlgorithmECDSAWithSHA384:          {"sha384", ""},
	kmip.DigitalSignatureAlgorithmECDSAWithSHA512:          {"sha512", ""},
}

// signatureParams turns the cryptographic parameters of a Sign or Signature
// Verify request into the engine's hash, padding and PSS salt length.
func signatureParams(p *kmip.CryptographicParameters) (hash, padding string, salt int, err error) {
	if p == nil {
		return "", "", 0, nil
	}

	if p.HashingAlgorithm != 0 {
		var ok bool
		if hash, ok = hashingTokens[p.HashingAlgorithm]; !ok {
			return "", "", 0, notSupported("hashing algorithm %v is not supported", p.HashingAlgorithm)
		}
	}

	if p.DigitalSignatureAlgorithm != 0 {
		alg, ok := signatureAlgorithms[p.DigitalSignatureAlgorithm]
		if !ok {
			return "", "", 0, notSupported("digital signature algorithm %v is not supported", p.DigitalSignatureAlgorithm)
		}
		if alg.hash != "" {
			hash = alg.hash
		}
		padding = alg.padding
	}

	switch p.PaddingMethod {
	case 0:
	case kmip.PaddingMethodPKCS1V1_5:
		padding = "pkcs1v15"
	case kmip.PaddingMethodPSS:
		padding = "pss"
	default:
		return "", "", 0, notSupported("padding method %v is not supported for signatures", p.PaddingMethod)
	}

	if p.SaltLength != nil {
		salt = int(*p.SaltLength)
	}
	return hash, padding, salt, nil
}

// signInput resolves the data or digest of a Sign or Signature Verify request.
func signInput(data, digested []byte) (input []byte, prehashed bool, err error) {
	switch {
	case len(data) > 0 && len(digested) > 0:
		return nil, false, errField("give either data or a digest, not both")
	case len(digested) > 0:
		return digested, true, nil
	}
	return data, false, nil
}

func signRequest(hash, padding string, salt int, input []byte, prehashed bool) map[string]any {
	req := map[string]any{
		"data":      base64.StdEncoding.EncodeToString(input),
		"prehashed": prehashed,
	}
	if hash != "" {
		req["hash"] = hash
	}
	if padding != "" {
		req["padding"] = padding
	}
	if salt > 0 {
		req["salt_length"] = salt
	}
	return req
}

func (o *objectOps) sign(ctx context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	hash, padding, salt, err := signatureParams(req.CryptographicParameters)
	if err != nil {
		return nil, err
	}
	input, prehashed, err := signInput(req.Data, req.DigestedData)
	if err != nil {
		return nil, err
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "sign/"+uid, signRequest(hash, padding, salt, input, prehashed))
	if err != nil {
		return nil, err
	}
	sig, err := decodeEngineBytes(resp, "signature")
	if err != nil {
		return nil, err
	}
	return &payloads.SignResponsePayload{UniqueIdentifier: uid, SignatureData: sig}, nil
}

func (o *objectOps) signatureVerify(ctx context.Context, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	hash, padding, salt, err := signatureParams(req.CryptographicParameters)
	if err != nil {
		return nil, err
	}
	input, prehashed, err := signInput(req.Data, req.DigestedData)
	if err != nil {
		return nil, err
	}

	data := signRequest(hash, padding, salt, input, prehashed)
	data["signature"] = base64.StdEncoding.EncodeToString(req.SignatureData)
	resp, err := o.call(ctx, logical.UpdateOperation, "verify/"+uid, data)
	if err != nil {
		return nil, err
	}

	return &payloads.SignatureVerifyResponsePayload{UniqueIdentifier: uid, ValidityIndicator: validity(resp)}, nil
}

func validity(resp *logical.Response) kmip.ValidityIndicator {
	if valid, _ := resp.Data["valid"].(bool); valid {
		return kmip.ValidityIndicatorValid
	}
	return kmip.ValidityIndicatorInvalid
}

// macHash names the hash a MAC request asks for, from the HMAC algorithm or
// the hashing algorithm of its cryptographic parameters. The engine checks it
// against the key's own algorithm.
func macHash(p *kmip.CryptographicParameters) (string, error) {
	if p == nil {
		return "", nil
	}
	if p.CryptographicAlgorithm != 0 {
		token, ok := algorithmTokens[p.CryptographicAlgorithm]
		if !ok || len(token) <= len("hmac-") || token[:5] != "hmac-" {
			return "", notSupported("MAC algorithm %v is not supported", p.CryptographicAlgorithm)
		}
		return token[5:], nil
	}
	if p.HashingAlgorithm != 0 {
		token, ok := hashingTokens[p.HashingAlgorithm]
		if !ok {
			return "", notSupported("hashing algorithm %v is not supported", p.HashingAlgorithm)
		}
		return token, nil
	}
	return "", nil
}

func (o *objectOps) mac(ctx context.Context, req *MACRequestPayload) (*MACResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	hash, err := macHash(req.CryptographicParameters)
	if err != nil {
		return nil, err
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "mac/"+uid, map[string]any{
		"data": base64.StdEncoding.EncodeToString(req.Data),
		"hash": hash,
	})
	if err != nil {
		return nil, err
	}
	mac, err := decodeEngineBytes(resp, "mac")
	if err != nil {
		return nil, err
	}
	return &MACResponsePayload{UniqueIdentifier: uid, MACData: mac}, nil
}

func (o *objectOps) macVerify(ctx context.Context, req *MACVerifyRequestPayload) (*MACVerifyResponsePayload, error) {
	uid, err := target(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	hash, err := macHash(req.CryptographicParameters)
	if err != nil {
		return nil, err
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "mac-verify/"+uid, map[string]any{
		"data": base64.StdEncoding.EncodeToString(req.Data),
		"mac":  base64.StdEncoding.EncodeToString(req.MACData),
		"hash": hash,
	})
	if err != nil {
		return nil, err
	}
	return &MACVerifyResponsePayload{UniqueIdentifier: uid, ValidityIndicator: validity(resp)}, nil
}

func (o *objectOps) hash(ctx context.Context, req *payloads.HashRequestPayload) (*payloads.HashResponsePayload, error) {
	if err := rejectStreaming(req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	name, ok := hashingTokens[req.CryptographicParameters.HashingAlgorithm]
	if !ok {
		return nil, notSupported("hashing algorithm %v is not supported", req.CryptographicParameters.HashingAlgorithm)
	}

	resp, err := o.call(ctx, logical.UpdateOperation, "hash", map[string]any{
		"data": base64.StdEncoding.EncodeToString(req.Data),
		"hash": name,
	})
	if err != nil {
		return nil, err
	}
	sum, err := decodeEngineBytes(resp, "data")
	if err != nil {
		return nil, err
	}
	return &payloads.HashResponsePayload{Data: sum}, nil
}

func (o *objectOps) rngRetrieve(ctx context.Context, req *RNGRetrieveRequestPayload) (*RNGRetrieveResponsePayload, error) {
	resp, err := o.call(ctx, logical.UpdateOperation, "random", map[string]any{"length": int(req.DataLength)})
	if err != nil {
		return nil, err
	}
	data, err := decodeEngineBytes(resp, "data")
	if err != nil {
		return nil, err
	}
	return &RNGRetrieveResponsePayload{Data: data}, nil
}
