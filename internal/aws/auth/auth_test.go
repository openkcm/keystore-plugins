package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/internal/aws/auth"
	"github.com/openkcm/internal/aws/rolesanywhere"
	"github.com/openkcm/internal/common"
	"github.com/openkcm/utils/testcerts"
)

func TestSecretAuthMethod_GetCredentials(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]any
		wantErr    bool
		wantConfig *auth.AWSConfig
	}{
		{
			name: "Valid credentials without session token",
			config: map[string]any{
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
			},
			wantErr: false,
			wantConfig: &auth.AWSConfig{
				AccessKeyID:     "test-access-key-id",
				SecretAccessKey: "test-secret-access-key",
				SessionToken:    nil,
			},
		},
		{
			name: "Valid credentials with session token",
			config: map[string]any{
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
				"sessionToken":    "test-session-token",
			},
			wantErr: false,
			wantConfig: &auth.AWSConfig{
				AccessKeyID:     "test-access-key-id",
				SecretAccessKey: "test-secret-access-key",
				SessionToken:    new("test-session-token"),
			},
		},
		{
			name: "Missing accessKeyId",
			config: map[string]any{
				"secretAccessKey": "test-secret-access-key",
			},
			wantErr: true,
		},
		{
			name: "Missing secretAccessKey",
			config: map[string]any{
				"accessKeyId": "test-access-key-id",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config, err := structpb.NewStruct(tt.config)
			assert.NoError(t, err)

			reader, err := common.NewStructReader(config)
			assert.NoError(t, err)

			authMethod := &auth.SecretAuthMethod{}

			// Act
			awsConfig, err := authMethod.GetCredentials(context.Background(), reader)

			// Assert
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && awsConfig != nil {
				assert.Equal(t, tt.wantConfig.AccessKeyID, awsConfig.AccessKeyID)
				assert.Equal(t, tt.wantConfig.SecretAccessKey, awsConfig.SecretAccessKey)
				if tt.wantConfig.SessionToken != nil {
					assert.Equal(t, *tt.wantConfig.SessionToken, *awsConfig.SessionToken)
				} else {
					assert.Nil(t, awsConfig.SessionToken)
				}
			}
		})
	}
}

func TestCertificateAuthMethod_GetCredentials(t *testing.T) {
	privateKey, clientCert := testcerts.NewKeyAndCertPEM(t)

	tests := []struct {
		name                           string
		config                         map[string]any
		mockCreateRolesAnywhereSession func(ctx context.Context, params rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error)
		wantErr                        bool
		expectedError                  error
	}{
		{
			name: "Valid credentials",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			mockCreateRolesAnywhereSession: func(ctx context.Context, params rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error) {
				provider := credentials.NewStaticCredentialsProvider(
					"mock-access-key-id",
					"mock-secret-access-key",
					"mock-session-token",
				)
				return &provider, nil
			},
			wantErr: false,
		},
		{
			name: "Missing roleArn",
			config: map[string]any{
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing trustAnchorArn",
			config: map[string]any{
				"roleArn":    "test-role-arn",
				"profileArn": "test-profile-arn",
				"clientCert": clientCert,
				"privateKey": privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing profileArn",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing clientCert",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"privateKey":     privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing privateKey",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
			},
			wantErr: true,
		},
		{
			name: "Invalid clientCert",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     "invalid-base64",
				"privateKey":     privateKey,
			},
			wantErr:       true,
			expectedError: auth.ErrLoadCert,
		},
		{
			name: "Invalid privateKey",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     "invalid-base64",
			},
			wantErr:       true,
			expectedError: auth.ErrLoadPrivateKey,
		},
		{
			name: "Error creating roles anywhere session",
			config: map[string]any{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			mockCreateRolesAnywhereSession: func(ctx context.Context, params rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error) {
				return nil, errors.New("mock error")
			},
			wantErr:       true,
			expectedError: auth.ErrCreateRolesAnywhereSession,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := structpb.NewStruct(tt.config)
			assert.NoError(t, err)

			reader, err := common.NewStructReader(config)
			assert.NoError(t, err)

			authMethod := &auth.CertificateAuthMethod{
				CreateRolesAnywhereSessionFunc: tt.mockCreateRolesAnywhereSession,
			}

			awsConfig, err := authMethod.GetCredentials(context.Background(), reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
				t.Errorf("GetCredentials() error = %v, expectedError %v", err, tt.expectedError)
			}

			if !tt.wantErr && awsConfig != nil {
				assert.Equal(t, "mock-access-key-id", awsConfig.AccessKeyID)
				assert.Equal(t, "mock-secret-access-key", awsConfig.SecretAccessKey)
				assert.Equal(t, "mock-session-token", *awsConfig.SessionToken)
			}
		})
	}
}
