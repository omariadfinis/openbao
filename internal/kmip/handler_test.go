package kmip

import (
	"context"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"
)

func discover(client *kmipclient.Client, versions ...kmip.ProtocolVersion) (*payloads.DiscoverVersionsResponsePayload, error) {
	resp, err := client.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{ProtocolVersion: versions})
	if err != nil {
		return nil, err
	}
	return resp.(*payloads.DiscoverVersionsResponsePayload), nil
}

func TestDiscoverVersions(t *testing.T) {
	client := kmiptest.NewClientAndServer(t, NewHandler())

	// The client negotiates the highest mutually supported version on connect.
	require.Equal(t, kmip.V1_4, client.Version())

	resp, err := discover(client, kmip.V1_4, kmip.V1_0, kmip.V2_0)
	require.NoError(t, err)
	require.Equal(t, []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_0}, resp.ProtocolVersion)
}

func TestDiscoverVersions_All(t *testing.T) {
	client := kmiptest.NewClientAndServer(t, NewHandler())

	resp, err := discover(client)
	require.NoError(t, err)
	require.Equal(t, []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_3, kmip.V1_2, kmip.V1_1, kmip.V1_0}, resp.ProtocolVersion)
}

func TestQuery(t *testing.T) {
	client := kmiptest.NewClientAndServer(t, NewHandler())

	resp, err := client.Query().Operations().Objects().ServerInformation().Exec()
	require.NoError(t, err)
	require.ElementsMatch(t, []kmip.Operation{kmip.OperationDiscoverVersions, kmip.OperationQuery}, resp.Operations)
	require.Empty(t, resp.ObjectType)
	require.Equal(t, VendorIdentification, resp.VendorIdentification)
}

func TestQuery_OnlyRequestedFunctions(t *testing.T) {
	client := kmiptest.NewClientAndServer(t, NewHandler())

	resp, err := client.Query().ServerInformation().Exec()
	require.NoError(t, err)
	require.Empty(t, resp.Operations)
	require.Equal(t, VendorIdentification, resp.VendorIdentification)
}

func TestUnsupportedOperation(t *testing.T) {
	client := kmiptest.NewClientAndServer(t, NewHandler())

	resp, err := client.Activate("unknown").Exec()
	require.Nil(t, resp)
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ResultReasonOperationNotSupported))
}
