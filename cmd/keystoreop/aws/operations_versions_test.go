package main_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	ap "github.com/openkcm/cmd/keystoreop/aws"
	awsauth "github.com/openkcm/internal/aws/auth"
	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/internal/aws/plugins/keystoreop/mock"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
)

type clientFactory = func(context.Context, *kscommonv1.KeystoreInstanceConfig, string) (*aws.Client, error)

func newTestPlugin(factory clientFactory) *ap.AWSPlugin {
	p := ap.NewAWSPlugin(factory, buildInfo)
	p.SetLogger(hclog.New(&hclog.LoggerOptions{Level: hclog.Error, Name: "test"}))

	return p
}

func mockFactory(client *mock.Mock) clientFactory {
	return func(context.Context, *kscommonv1.KeystoreInstanceConfig, string) (*aws.Client, error) {
		return aws.NewClientForTests(client), nil
	}
}

func failingFactory(err error) clientFactory {
	return func(context.Context, *kscommonv1.KeystoreInstanceConfig, string) (*aws.Client, error) {
		return nil, err
	}
}

// errorReason returns the ErrorInfo reason attached to a gRPC status error.
func errorReason(t *testing.T, err error) string {
	t.Helper()

	st, ok := status.FromError(err)
	if !assert.True(t, ok, "expected gRPC status error, got %v", err) {
		return ""
	}

	for _, detail := range st.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}

	return ""
}

func accessDeniedError() error {
	return &smithy.OperationError{
		ServiceID:     "KMS",
		OperationName: "ListKeyRotations",
		Err:           &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"},
	}
}

func TestAWS_GetKeyVersions(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		p := newTestPlugin(mockFactory(happyPathMock))

		resp, err := p.GetKeyVersions(t.Context(), &operationsv1.GetKeyVersionsRequest{
			Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
		})

		if !assert.NoError(t, err) || !assert.Len(t, resp.GetVersions(), 1) {
			return
		}
		assert.Equal(t, "mocked-key-material-id", resp.GetVersions()[0].GetVersionId())
		assert.True(t, resp.GetVersions()[0].GetCreationTime().AsTime().Equal(now))
	})

	t.Run("Error_AccessDenied", func(t *testing.T) {
		client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).WithListKeyRotationsFunc(
			func(context.Context, *kms.ListKeyRotationsInput, ...func(*kms.Options)) (*kms.ListKeyRotationsOutput, error) {
				return nil, accessDeniedError()
			})
		p := newTestPlugin(mockFactory(client))

		resp, err := p.GetKeyVersions(t.Context(), &operationsv1.GetKeyVersionsRequest{
			Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ap.GrpcErrorReasonListKeyVersionsDenied, errorReason(t, err))
	})

	t.Run("Error_ListKeyRotations", func(t *testing.T) {
		p := newTestPlugin(mockFactory(errorMock))

		resp, err := p.GetKeyVersions(t.Context(), &operationsv1.GetKeyVersionsRequest{
			Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
		})

		assert.ErrorIs(t, err, aws.ErrListKeyRotationsFailed)
		assert.Nil(t, resp)
	})

	t.Run("Error_ProviderAuthentication", func(t *testing.T) {
		p := newTestPlugin(failingFactory(awsauth.ErrCreateRolesAnywhereSession))

		resp, err := p.GetKeyVersions(t.Context(), &operationsv1.GetKeyVersionsRequest{
			Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ap.GrpcErrorReasonGenericAuthError, errorReason(t, err))
	})

	t.Run("Error_ClientFactory", func(t *testing.T) {
		p := newTestPlugin(failingFactory(errForced))

		resp, err := p.GetKeyVersions(t.Context(), &operationsv1.GetKeyVersionsRequest{
			Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
		})

		assert.ErrorIs(t, err, errForced)
		assert.Nil(t, resp)
	})
}

func TestAWS_RolesAnywhereErrorReasons(t *testing.T) {
	tests := []struct {
		message string
		want    string
	}{
		{"Untrusted signing certificate", ap.GrpcErrorReasonUntrustedCert},
		{"Unable to assume role", ap.GrpcErrorReasonCannotAssumeRole},
		{"Specified Trust Anchor wasn't found", ap.GrpcErrorReasonTrustAnchorNotFound},
		{"Requested Role isn't one of those listed in the Profile", ap.GrpcErrorReasonRoleNotInProfile},
		{"Invalid or empty profile provided", ap.GrpcErrorReasonProfileNotFound},
		{"something unexpected", ap.GrpcErrorReasonGenericAuthError},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			err := fmt.Errorf("%w: %s", awsauth.ErrCreateRolesAnywhereSession, tt.message)
			p := newTestPlugin(failingFactory(err))

			resp, err := p.GetKey(t.Context(), &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
			})

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, tt.want, errorReason(t, err))
		})
	}
}
