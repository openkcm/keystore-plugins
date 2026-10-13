package main_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	ap "github.com/openkcm/cmd/keystoreop/aws"
	keystoreop "github.com/openkcm/internal/aws/plugins/keystoreop"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"
)

const accessKeyAuthYAML = `
auth:
  method: accessKey
  accessKey:
    accessKeyId:
      value: plugin-key
    secretAccessKey:
      value: plugin-secret
`

const assumeRoleAuthYAML = `
auth:
  method: assumeRole
  accessKey:
    accessKeyId:
      value: plugin-key
    secretAccessKey:
      value: plugin-secret
  assumeRole:
    source: accessKey
    allowedRoleArns:
      - "arn:aws:iam::*:role/openkcm-*"
`

// capturingFactory records the credentials the plugin resolved for the client.
func capturingFactory(got *awssdk.Credentials) ap.ClientFactory {
	return func(ctx context.Context, _ string, creds awssdk.CredentialsProvider) (*keystoreop.Client, error) {
		value, err := creds.Retrieve(ctx)
		if err != nil {
			return nil, err
		}

		*got = value

		return keystoreop.NewClientForTests(happyPathMock), nil
	}
}

func instanceConfig(t *testing.T, values map[string]any) *kscommonv1.KeystoreInstanceConfig {
	t.Helper()

	s, err := structpb.NewStruct(values)
	assert.NoError(t, err)

	return &kscommonv1.KeystoreInstanceConfig{Values: s}
}

func TestConfigure_Auth(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantCode codes.Code
	}{
		{"Empty", "", codes.OK},
		{"OtherSettingsOnly", "other: value\n", codes.OK},
		{"EmptyAuth", "auth: {}\n", codes.OK},
		{"PerRequestMethod", "auth:\n  method: perRequest\n", codes.OK},
		{"Ambient", "auth:\n  method: ambient\n", codes.OK},
		{"AccessKey", accessKeyAuthYAML, codes.OK},
		{"AssumeRole", assumeRoleAuthYAML, codes.OK},
		{"InvalidYAML", "auth: [", codes.InvalidArgument},
		{"MisspelledKey", "auth:\n  methd: accessKey\n", codes.InvalidArgument},
		{"UnknownMethod", "auth:\n  method: magic\n", codes.InvalidArgument},
		{"AccessKeyMissingSection", "auth:\n  method: accessKey\n", codes.InvalidArgument},
		{"DurationTooShort", "auth:\n  method: assumeRole\n  assumeRole:\n    duration: 1m\n", codes.InvalidArgument},
		{"RolesAnywhereMissingSection", "auth:\n  method: rolesAnywhere\n", codes.InvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPlugin(mockFactory(happyPathMock))

			resp, err := p.Configure(t.Context(), &configv1.ConfigureRequest{YamlConfiguration: tt.yaml})

			if tt.wantCode == codes.OK {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				return
			}

			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

func TestPlugin_RequestCredentialsByDefault(t *testing.T) {
	var got awssdk.Credentials

	p := newTestPlugin(capturingFactory(&got))

	_, err := p.GetKey(t.Context(), &operationsv1.GetKeyRequest{
		Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
	})

	assert.NoError(t, err)
	assert.Equal(t, "test-access-key-id", got.AccessKeyID)

	_, err = p.GetKey(t.Context(), &operationsv1.GetKeyRequest{
		Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: instanceConfig(t, map[string]any{})},
	})

	assert.ErrorContains(t, err, "authType")
}

func TestPlugin_ConfiguredCredentialsTakePrecedence(t *testing.T) {
	var got awssdk.Credentials

	p := newTestPlugin(capturingFactory(&got))

	_, err := p.Configure(t.Context(), &configv1.ConfigureRequest{YamlConfiguration: accessKeyAuthYAML})
	assert.NoError(t, err)

	// The request still carries its own access key, which must be ignored.
	resp, err := p.GetKey(t.Context(), &operationsv1.GetKeyRequest{
		Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: setupConfig(t)},
	})

	assert.NoError(t, err)
	assert.Equal(t, keyId, resp.GetKeyId())
	assert.Equal(t, "plugin-key", got.AccessKeyID)
}

func TestPlugin_AssumeRoleAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name       string
		values     map[string]any
		wantReason string
	}{
		{"MissingRole", map[string]any{}, ap.GrpcErrorReasonGenericAuthError},
		{
			"RoleNotAllowed",
			map[string]any{"roleArn": "arn:aws:iam::123456789012:role/admin"},
			ap.GrpcErrorReasonRoleNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPlugin(mockFactory(happyPathMock))

			_, err := p.Configure(t.Context(), &configv1.ConfigureRequest{YamlConfiguration: assumeRoleAuthYAML})
			assert.NoError(t, err)

			// Every RPC that needs a client reports the same authentication error.
			_, err = p.GetKey(t.Context(), &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: instanceConfig(t, tt.values)},
			})
			assert.Equal(t, tt.wantReason, errorReason(t, err))

			_, err = p.EnableKey(t.Context(), &operationsv1.EnableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId, Config: instanceConfig(t, tt.values)},
			})
			assert.Equal(t, tt.wantReason, errorReason(t, err))
		})
	}
}
