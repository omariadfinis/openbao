package kmip

import (
	"time"

	"github.com/ovh/kmip-go"
)

// The kmip-go library has no payloads for MAC, MAC Verify, RNG Retrieve and
// Check. They are defined here from the KMIP 1.4 specification and registered
// with the library, which also lets the library's client send them.

func init() {
	kmip.RegisterOperationPayload[MACRequestPayload, MACResponsePayload](kmip.OperationMAC)
	kmip.RegisterOperationPayload[MACVerifyRequestPayload, MACVerifyResponsePayload](kmip.OperationMACVerify)
	kmip.RegisterOperationPayload[RNGRetrieveRequestPayload, RNGRetrieveResponsePayload](kmip.OperationRNGRetrieve)
	kmip.RegisterOperationPayload[CheckRequestPayload, CheckResponsePayload](kmip.OperationCheck)
}

// MACRequestPayload is the request of the MAC operation.
type MACRequestPayload struct {
	UniqueIdentifier        string `ttlv:",omitempty"`
	CryptographicParameters *kmip.CryptographicParameters
	Data                    []byte `ttlv:",omitempty"`
	CorrelationValue        []byte `ttlv:",omitempty,version=v1.3.."`
	InitIndicator           *bool  `ttlv:",version=v1.3.."`
	FinalIndicator          *bool  `ttlv:",version=v1.3.."`
}

func (*MACRequestPayload) Operation() kmip.Operation { return kmip.OperationMAC }

// MACResponsePayload is the response of the MAC operation.
type MACResponsePayload struct {
	UniqueIdentifier string
	MACData          []byte `ttlv:",omitempty"`
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
}

func (*MACResponsePayload) Operation() kmip.Operation { return kmip.OperationMAC }

// MACVerifyRequestPayload is the request of the MAC Verify operation.
type MACVerifyRequestPayload struct {
	UniqueIdentifier        string `ttlv:",omitempty"`
	CryptographicParameters *kmip.CryptographicParameters
	Data                    []byte `ttlv:",omitempty"`
	MACData                 []byte `ttlv:",omitempty"`
	CorrelationValue        []byte `ttlv:",omitempty,version=v1.3.."`
	InitIndicator           *bool  `ttlv:",version=v1.3.."`
	FinalIndicator          *bool  `ttlv:",version=v1.3.."`
}

func (*MACVerifyRequestPayload) Operation() kmip.Operation { return kmip.OperationMACVerify }

// MACVerifyResponsePayload is the response of the MAC Verify operation.
type MACVerifyResponsePayload struct {
	UniqueIdentifier  string
	ValidityIndicator kmip.ValidityIndicator
	CorrelationValue  []byte `ttlv:",omitempty,version=v1.3.."`
}

func (*MACVerifyResponsePayload) Operation() kmip.Operation { return kmip.OperationMACVerify }

// RNGRetrieveRequestPayload is the request of the RNG Retrieve operation.
type RNGRetrieveRequestPayload struct {
	DataLength int32
}

func (*RNGRetrieveRequestPayload) Operation() kmip.Operation { return kmip.OperationRNGRetrieve }

// RNGRetrieveResponsePayload is the response of the RNG Retrieve operation.
type RNGRetrieveResponsePayload struct {
	Data []byte
}

func (*RNGRetrieveResponsePayload) Operation() kmip.Operation { return kmip.OperationRNGRetrieve }

// CheckRequestPayload is the request of the Check operation.
type CheckRequestPayload struct {
	UniqueIdentifier       string `ttlv:",omitempty"`
	UsageLimitsCount       *int64
	CryptographicUsageMask kmip.CryptographicUsageMask `ttlv:",omitempty"`
	LeaseTime              *time.Duration
}

func (*CheckRequestPayload) Operation() kmip.Operation { return kmip.OperationCheck }

// CheckResponsePayload is the response of the Check operation.
type CheckResponsePayload struct {
	UniqueIdentifier       string
	UsageLimitsCount       *int64
	CryptographicUsageMask kmip.CryptographicUsageMask `ttlv:",omitempty"`
	LeaseTime              *time.Duration
}

func (*CheckResponsePayload) Operation() kmip.Operation { return kmip.OperationCheck }
