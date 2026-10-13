package main_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	ap "github.com/openkcm/cmd/keystoreop/aws"
	awsauth "github.com/openkcm/internal/aws/auth"
	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/internal/aws/plugins/keystoreop/mock"
	"github.com/openkcm/internal/common/keystoreop"
	protoDef "github.com/openkcm/pkg/proto"
	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	"github.com/openkcm/utils/ptr"
)

const (
	keyId        = "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef"
	invalidKeyID = "invalid-key-id"

	validRoleArnPrefix        = "arn:aws:iam::123456789012:role/"
	validTrustAnchorArnPrefix = "arn:aws:rolesanywhere:us-west-2:123456789012:trust-anchor/"
	validProfileArnPrefix     = "arn:aws:rolesanywhere:us-west-2:123456789012:profile/"
)

func setupConfig(t *testing.T) *kscommonv1.KeystoreInstanceConfig {
	t.Helper()

	configMap := map[string]interface{}{
		"accessKeyId":     "test-access-key-id",
		"secretAccessKey": "test-secret-access-key",
	}

	anyConfig, err := structpb.NewStruct(configMap)
	assert.NoError(t, err)

	return &kscommonv1.KeystoreInstanceConfig{
		Values: anyConfig,
	}
}

func TestAWS_GetKey(t *testing.T) {
	tests := []struct {
		name         string
		client       *mock.Mock
		setupFactory func() func(context.Context, *kscommonv1.KeystoreInstanceConfig, string) (*aws.Client, error)
		req          *operationsv1.GetKeyRequest
		want         *operationsv1.GetKeyResponse
		wantErr      bool
		errContains  string
	}{
		{
			name:   "Success",
			client: happyPathMock,
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			want: &operationsv1.GetKeyResponse{
				KeyId:     keyId,
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
				Status:    string(keystoreop.KeyStateEnabled),
				Usage:     "ENCRYPT_DECRYPT",
			},
			wantErr: false,
		},
		{
			name:   "Error_InvalidKeyID",
			client: happyPathMock,
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: invalidKeyID},
			},
			wantErr: true,
		},
		{
			name:   "Error_GetKey",
			client: errorMock,
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr: true,
		},
		{
			name: "Error_KeyNotFound",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithDescribeKeyFunc(func(
					_ context.Context,
					_ *kms.DescribeKeyInput,
					_ ...func(*kms.Options),
				) (*kms.DescribeKeyOutput, error) {
					return nil, &types.NotFoundException{}
				}),
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr:     true,
			errContains: commonErrs.StatusKeyNotFound.Message(),
		},
		{
			name:   "Error_ProviderAuthentication",
			client: happyPathMock,
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr: true,
			setupFactory: func() func(context.Context, *kscommonv1.KeystoreInstanceConfig, string) (*aws.Client, error) {
				return func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return nil, awsauth.ErrCreateRolesAnywhereSession
				}
			},
			errContains: commonErrs.StatusProviderAuthenticationError.Message(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config := setupConfig(t)
			tt.req.Parameters.Config = config

			factory := func(
				ctx context.Context,
				cfg *kscommonv1.KeystoreInstanceConfig,
				region string,
			) (*aws.Client, error) {
				return aws.NewClientForTests(tt.client), nil
			}

			if tt.setupFactory != nil {
				factory = tt.setupFactory()
			}

			p := ap.NewAWSPlugin(factory, buildInfo)

			p.SetLogger(hclog.New(&hclog.LoggerOptions{Level: hclog.Debug, Name: "test"}))

			// Act
			resp, err := p.GetKey(context.Background(), tt.req)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, tt.want.KeyId, resp.KeyId)
			assert.Equal(t, tt.want.Algorithm, resp.Algorithm)
			assert.Equal(t, tt.want.Status, resp.Status)
			assert.Equal(t, tt.want.Usage, resp.Usage)
		})
	}
}

func TestAWS_CreateKey(t *testing.T) {
	tests := []struct {
		name      string
		client    *mock.Mock
		req       *operationsv1.CreateKeyRequest
		wantKeyID string
		wantErr   bool
	}{
		{
			name:   "Success_AES256",
			client: happyPathMock,
			req: &operationsv1.CreateKeyRequest{
				Id:        ptr.PointTo(expectedID),
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
				KeyType:   operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED,
			},
			wantKeyID: expectedKeyArn,
			wantErr:   false,
		},
		{
			name:   "Success_RSA3072",
			client: happyPathMock,
			req: &operationsv1.CreateKeyRequest{
				Id:        ptr.PointTo(expectedID),
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
				KeyType:   operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED,
			},
			wantKeyID: expectedKeyArn,
			wantErr:   false,
		},
		{
			name:   "Success_RSA4096",
			client: happyPathMock,
			req: &operationsv1.CreateKeyRequest{
				Id:        ptr.PointTo(expectedID),
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096,
				KeyType:   operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED,
			},
			wantKeyID: expectedKeyArn,
			wantErr:   false,
		},
		{
			name:   "Error_CreateKey",
			client: errorMock,
			req: &operationsv1.CreateKeyRequest{
				Id:        ptr.PointTo(expectedID),
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			},
			wantErr: true,
		},
		{
			name:   "Error_InvalidAlgorithm",
			client: happyPathMock,
			req: &operationsv1.CreateKeyRequest{
				Id:        ptr.PointTo(expectedID),
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
			},
			wantErr: true,
		},
		{
			name:   "Error_MissingID",
			client: happyPathMock,
			req: &operationsv1.CreateKeyRequest{
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config := setupConfig(t)
			tt.req.Config = config

			p := ap.NewAWSPlugin(
				func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return aws.NewClientForTests(tt.client), nil
				},
				buildInfo,
			)

			// Act
			resp, err := p.CreateKey(context.Background(), tt.req)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, tt.wantKeyID, resp.KeyId)
		})
	}
}

func TestAWS_DeleteKey(t *testing.T) {
	tests := []struct {
		name    string
		client  *mock.Mock
		req     *operationsv1.DeleteKeyRequest
		wantErr bool
	}{
		{
			name:   "Success",
			client: happyPathMock,
			req: &operationsv1.DeleteKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
				Window:     ptr.PointTo(int32(7)),
			},
			wantErr: false,
		},
		{
			name:   "Error_InvalidKeyID",
			client: happyPathMock,
			req: &operationsv1.DeleteKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: invalidKeyID},
				Window:     ptr.PointTo(int32(7)),
			},
			wantErr: true,
		},
		{
			name:   "Error_DeleteKey",
			client: errorMock,
			req: &operationsv1.DeleteKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
				Window:     ptr.PointTo(int32(7)),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config := setupConfig(t)
			tt.req.Parameters.Config = config

			p := ap.NewAWSPlugin(
				func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return aws.NewClientForTests(tt.client), nil
				},
				buildInfo,
			)

			// Act
			resp, err := p.DeleteKey(context.Background(), tt.req)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

func TestAWS_EnableKey(t *testing.T) {
	tests := []struct {
		name    string
		client  *mock.Mock
		req     *operationsv1.EnableKeyRequest
		wantErr bool
	}{
		{
			name:   "Success",
			client: happyPathMock,
			req: &operationsv1.EnableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr: false,
		},
		{
			name:   "Error_InvalidKeyID",
			client: happyPathMock,
			req: &operationsv1.EnableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: invalidKeyID},
			},
			wantErr: true,
		},
		{
			name:   "Error_DeleteKey",
			client: errorMock,
			req: &operationsv1.EnableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config := setupConfig(t)
			tt.req.Parameters.Config = config

			p := ap.NewAWSPlugin(
				func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return aws.NewClientForTests(tt.client), nil
				},
				buildInfo,
			)

			// Act
			resp, err := p.EnableKey(context.Background(), tt.req)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

func TestAWS_DisableKey(t *testing.T) {
	tests := []struct {
		name    string
		client  *mock.Mock
		req     *operationsv1.DisableKeyRequest
		wantErr bool
	}{
		{
			name:   "Success",
			client: happyPathMock,
			req: &operationsv1.DisableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr: false,
		},
		{
			name:   "Error_InvalidKeyID",
			client: happyPathMock,
			req: &operationsv1.DisableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: invalidKeyID},
			},
			wantErr: true,
		},
		{
			name:   "Error_DeleteKey",
			client: errorMock,
			req: &operationsv1.DisableKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config := setupConfig(t)
			tt.req.Parameters.Config = config

			p := ap.NewAWSPlugin(
				func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return aws.NewClientForTests(tt.client), nil
				},
				buildInfo,
			)

			// Act
			resp, err := p.DisableKey(context.Background(), tt.req)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

func TestExtractRegionFromARN(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		want    string
		wantErr bool
	}{
		{
			name:    "Valid ARN",
			arn:     "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			want:    "us-west-2",
			wantErr: false,
		},
		{
			name:    "Invalid ARN format",
			arn:     "invalid-arn",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Missing region",
			arn:     "arn:aws:kms::123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Short ARN",
			arn:     "arn:aws:kms:us-west-2",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := ap.ExtractRegionFromARN(tt.arn)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestAWS_GetImportParametersResponse(t *testing.T) {
	tests := []struct {
		name      string
		client    *mock.Mock
		req       *operationsv1.GetImportParametersRequest
		wantKeyID string
		wantErr   bool
	}{
		{
			name:   "Success_AES256",
			client: happyPathMock,
			req: &operationsv1.GetImportParametersRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
				Algorithm:  operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			},
			wantKeyID: keyId,
			wantErr:   false,
		},
		{
			name:   "Success_RSA3072",
			client: happyPathMock,
			req: &operationsv1.GetImportParametersRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
				Algorithm:  operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
			},
			wantKeyID: keyId,
			wantErr:   false,
		},
		{
			name:   "Success_RSA4096",
			client: happyPathMock,
			req: &operationsv1.GetImportParametersRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
				Algorithm:  operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096,
			},
			wantKeyID: keyId,
			wantErr:   false,
		},
		{
			name:   "Error_InvalidKeyID",
			client: happyPathMock,
			req: &operationsv1.GetImportParametersRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: invalidKeyID},
				Algorithm:  operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			},
			wantErr: true,
		},
		{
			name:   "Error_Client",
			client: errorMock,
			req: &operationsv1.GetImportParametersRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
				Algorithm:  operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := setupConfig(t)
			tt.req.Parameters.Config = config

			p := ap.NewAWSPlugin(
				func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return aws.NewClientForTests(tt.client), nil
				},
				buildInfo,
			)

			resp, err := p.GetImportParameters(context.Background(), tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, tt.wantKeyID, resp.KeyId)
			assert.NotNil(t, resp.ImportParameters)
		})
	}
}

func TestAWS_ImportKeyMaterial(t *testing.T) {
	tests := []struct {
		name         string
		client       *mock.Mock
		req          *operationsv1.ImportKeyMaterialRequest
		importParams map[string]interface{}
		wantErr      bool
		wantStatus   *status.Status
	}{
		{
			name:   "Success",
			client: happyPathMock,
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: keyId},
				EncryptedKeyMaterial: base64.StdEncoding.EncodeToString([]byte("material")),
			},
			importParams: map[string]interface{}{
				"providerParams": base64.StdEncoding.EncodeToString([]byte("token")),
			},
			wantErr: false,
		},
		{
			name:   "Error_InvalidKeyID",
			client: happyPathMock,
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: invalidKeyID},
				EncryptedKeyMaterial: base64.StdEncoding.EncodeToString([]byte("material")),
			},
			importParams: map[string]interface{}{
				"providerParams": base64.StdEncoding.EncodeToString([]byte("token")),
			},
			wantErr: true,
		},
		{
			name:   "Error_Client",
			client: errorMock,
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: keyId},
				EncryptedKeyMaterial: base64.StdEncoding.EncodeToString([]byte("material")),
			},
			importParams: map[string]interface{}{
				"providerParams": base64.StdEncoding.EncodeToString([]byte("token")),
			},
			wantErr: true,
		},
		{
			name:   "Error_InvalidImportTokenBase64",
			client: happyPathMock,
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: keyId},
				EncryptedKeyMaterial: base64.StdEncoding.EncodeToString([]byte("material")),
			},
			importParams: map[string]interface{}{
				"providerParams": "!!!not-base64!!!",
			},
			wantErr: true,
		},
		{
			name:   "Error_MissingImportToken",
			client: happyPathMock,
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: keyId},
				EncryptedKeyMaterial: base64.StdEncoding.EncodeToString([]byte("material")),
			},
			importParams: map[string]interface{}{},
			wantErr:      true,
		},
		{
			name:   "Error_InvalidEncryptedKeyMaterialBase64",
			client: happyPathMock,
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: keyId},
				EncryptedKeyMaterial: "!!!not-base64!!!",
			},
			importParams: map[string]interface{}{
				"providerParams": base64.StdEncoding.EncodeToString([]byte("token")),
			},
			wantErr: true,
		},
		{
			name: "Error_InvalidCiphertext",
			client: mock.NewMock().WithImportKeyMaterialFunc(
				func(_ context.Context, _ *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
					return nil, &types.InvalidCiphertextException{Message: ptr.PointTo("decryption failed")}
				}),
			req: &operationsv1.ImportKeyMaterialRequest{
				Parameters:           &operationsv1.RequestParameters{KeyId: keyId},
				EncryptedKeyMaterial: base64.StdEncoding.EncodeToString([]byte("material")),
			},
			importParams: map[string]interface{}{
				"providerParams": base64.StdEncoding.EncodeToString([]byte("token")),
			},
			wantErr:    true,
			wantStatus: commonErrs.StatusImportKeyMaterialFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := setupConfig(t)
			tt.req.Parameters.Config = config

			// Convert importParams to *structpb.Struct
			if tt.importParams != nil {
				s, err := structpb.NewStruct(tt.importParams)
				assert.NoError(t, err)
				tt.req.ImportParameters = s
			} else {
				tt.req.ImportParameters = nil
			}

			p := ap.NewAWSPlugin(
				func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
					return aws.NewClientForTests(tt.client), nil
				},
				buildInfo,
			)
			p.SetLogger(hclog.NewNullLogger())

			resp, err := p.ImportKeyMaterial(context.Background(), tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.wantStatus != nil {
					assert.True(t, commonErrs.IsStatus(err, tt.wantStatus))
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})
	}
}

func TestValidateKey(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
		buildInfo,
	)

	tests := []struct {
		name     string
		request  *operationsv1.ValidateKeyRequest
		expected *operationsv1.ValidateKeyResponse
	}{
		{
			name: "Valid Key",
			request: &operationsv1.ValidateKeyRequest{
				KeyType:     operationsv1.KeyType_KEY_TYPE_HYOK,
				Algorithm:   operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
				Region:      "us-east-1",
				NativeKeyId: "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
			},
			expected: ptr.PointTo(operationsv1.ValidateKeyResponse{
				IsValid: true,
			}),
		},
		{
			name: "Unspecified Key Type",
			request: &operationsv1.ValidateKeyRequest{
				KeyType:   operationsv1.KeyType_KEY_TYPE_UNSPECIFIED,
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
				Region:    "us-east-1",
			},
			expected: ptr.PointTo(operationsv1.ValidateKeyResponse{
				IsValid: false,
				Message: "key type must be specified",
			}),
		},
		{
			name: "Unspecified Algorithm",
			request: &operationsv1.ValidateKeyRequest{
				KeyType:   operationsv1.KeyType_KEY_TYPE_HYOK,
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
				Region:    "us-east-1",
			},
			expected: ptr.PointTo(operationsv1.ValidateKeyResponse{
				IsValid: false,
				Message: "algorithm must be specified",
			}),
		},
		{
			name: "Invalid Region",
			request: &operationsv1.ValidateKeyRequest{
				KeyType:     operationsv1.KeyType_KEY_TYPE_HYOK,
				Algorithm:   operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
				Region:      "invalid-region",
				NativeKeyId: "arn:aws:kms:invalid-region:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
			},
			expected: ptr.PointTo(operationsv1.ValidateKeyResponse{
				IsValid: false,
				Message: "invalid region: invalid-region",
			}),
		},
		{
			name: "Invalid ARN",
			request: &operationsv1.ValidateKeyRequest{
				KeyType:     operationsv1.KeyType_KEY_TYPE_HYOK,
				Algorithm:   operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
				Region:      "us-east-1",
				NativeKeyId: "invalid-arn",
			},
			expected: ptr.PointTo(operationsv1.ValidateKeyResponse{
				IsValid: false,
				Message: "failed to extract region from ARN: invalid-arn, error: invalid ARN",
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, _ := p.ValidateKey(context.Background(), tt.request)
			assert.Equal(t, tt.expected, response)
		})
	}
}

func TestValidateKeyAccessData(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
		buildInfo,
	)

	tests := []struct {
		name                  string
		request               *operationsv1.ValidateKeyAccessDataRequest
		valid                 bool
		expectedErrorStatus   status.Status
		expectedErrorReason   string
		expectedErrorMetadata map[string]string
	}{
		{
			name: "Valid Management and Crypto Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TA1"),
								"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "P1"),
								"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "R1"),
							},
						}),
						"instance2": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TA2"),
								"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "P2"),
								"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "R2"),
							},
						}),
					},
				},
			},
			valid: true,
		},
		{
			name: "Missing All Management Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: nil,
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "MISSING_FIELDS",
			expectedErrorMetadata: map[string]string{
				"type":          "management",
				"missingFields": "trustAnchorArn,profileArn,roleArn",
			},
		},
		{
			name: "Missing Part Management Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"profileArn": structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":    structpb.NewStringValue(validRoleArnPrefix + "Role"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "MISSING_FIELDS",
			expectedErrorMetadata: map[string]string{
				"type":          "management",
				"missingFields": "trustAnchorArn",
			},
		},
		{
			name: "Invalid trustAnchorArn in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue(validTrustAnchorArnPrefix + "Role"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "INVALID_TRUST_ANCHOR_ARN",
			expectedErrorMetadata: map[string]string{
				"type": "management",
			},
		},
		{
			name: "Invalid profileArn in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue("Profile"),
						"roleArn":        structpb.NewStringValue(validTrustAnchorArnPrefix + "Role"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "INVALID_PROFILE_ARN",
			expectedErrorMetadata: map[string]string{
				"type": "management",
			},
		},
		{
			name: "Invalid roleArn in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue("Role"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "INVALID_ROLE_ARN",
			expectedErrorMetadata: map[string]string{
				"type": "management",
			},
		},
		{
			name: "Not same account in management ARNs",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(
							"arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/TrustAnchor"),
						"profileArn": structpb.NewStringValue(
							"arn:aws:rolesanywhere:us-east-1:444455556666:profile/Profile"),
						"roleArn": structpb.NewStringValue(
							"arn:aws:iam::777788889999:role/Role"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "ARN_ACCOUNT_MISMATCH",
			expectedErrorMetadata: map[string]string{
				"type": "management",
			},
		},
		{
			name: "Invalid Crypto Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStringValue("invalid-data"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "INVALID_ACCESS_DATA_TYPE",
			expectedErrorMetadata: map[string]string{
				"instance": "instance1",
				"type":     "crypto",
			},
		},
		{
			name: "Empty Crypto Data for instance",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewNullValue(),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "MISSING_ACCESS_DATA",
			expectedErrorMetadata: map[string]string{
				"instance": "instance1",
				"type":     "crypto",
			},
		},
		{
			name: "Wrong data in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(""),
						"accessKeyId":    structpb.NewStringValue("X"),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "CANNOT_PARSE_DATA",
			expectedErrorMetadata: map[string]string{
				"type": "management",
			},
		},
		{
			name: "Wrong data in Crypto",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TA1"),
								"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "P1"),
								"accessKeyId":    structpb.NewStringValue("ABCD"),
							},
						}),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "CANNOT_PARSE_DATA",
			expectedErrorMetadata: map[string]string{
				"instance": "instance1",
				"type":     "crypto",
			},
		},
		{
			name: "Invalid ARNs in Crypto",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TrustAnchor"),
						"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "Profile"),
						"roleArn":        structpb.NewStringValue(validRoleArnPrefix + "Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue(validTrustAnchorArnPrefix + "TA1"),
								"profileArn":     structpb.NewStringValue(validProfileArnPrefix + "P1"),
								"roleArn":        structpb.NewStringValue("InvalidRoleArn"),
							},
						}),
					},
				},
			},
			expectedErrorStatus: *commonErrs.StatusInvalidKeyAccessData,
			expectedErrorReason: "INVALID_ROLE_ARN",
			expectedErrorMetadata: map[string]string{
				"instance": "instance1",
				"type":     "crypto",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := p.ValidateKeyAccessData(context.Background(), tt.request)
			if tt.valid {
				assert.NoError(t, err)
				assert.True(t, response.IsValid)
				if err != nil {
					reason, metadata := commonErrs.GetDetails(err)
					t.Errorf("Unexpected error details: reason=%s, metadata=%v", reason, metadata)
				}
				return
			}

			assert.True(t, commonErrs.IsStatus(err, &tt.expectedErrorStatus))

			reason, metadata := commonErrs.GetDetails(err)
			assert.Equal(t, tt.expectedErrorReason, reason)
			assert.Equal(t, tt.expectedErrorMetadata, metadata)
		})
	}
}

func TestExtractKeyRegion(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
		buildInfo,
	)

	tests := []struct {
		name     string
		request  *operationsv1.ExtractKeyRegionRequest
		expected *operationsv1.ExtractKeyRegionResponse
		errMsg   string
	}{
		{
			name: "Valid ARN",
			request: &operationsv1.ExtractKeyRegionRequest{
				NativeKeyId: "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv",
			},
			expected: &operationsv1.ExtractKeyRegionResponse{
				Region: "us-east-1",
			},
			errMsg: "",
		},
		{
			name: "Invalid ARN",
			request: &operationsv1.ExtractKeyRegionRequest{
				NativeKeyId: "invalid-arn",
			},
			expected: nil,
			errMsg:   "failed to extract region from ARN: invalid-arn, error: invalid ARN",
		},
		{
			name:     "Nil Request",
			request:  nil,
			expected: nil,
			errMsg:   "nil request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := p.ExtractKeyRegion(context.Background(), tt.request)
			if tt.errMsg != "" {
				assert.Nil(t, response)
				assert.EqualError(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, response)
			}
		})
	}
}

func TestTransformCryptoAccessData(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
		buildInfo,
	)

	tests := []struct {
		name       string
		inputJSON  []byte
		keyID      string
		wantErr    bool
		errMessage string
	}{
		{
			name: "Valid Input",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"instance1": {
						"trustAnchorArn": validTrustAnchorArnPrefix + "TrustAnchor1",
						"profileArn":     validProfileArnPrefix + "Profile1",
						"roleArn":        validRoleArnPrefix + "Role1",
					},
					"instance2": {
						"trustAnchorArn": validTrustAnchorArnPrefix + "TrustAnchor2",
						"profileArn":     validProfileArnPrefix + "Profile2",
						"roleArn":        validRoleArnPrefix + "Role2",
					},
				}
				bytes, _ := json.Marshal(data)
				return bytes
			}(),
			keyID:   "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr: false,
		},
		{
			name:       "Empty access data",
			inputJSON:  []byte(""),
			keyID:      "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr:    true,
			errMessage: "rpc error: code = InvalidArgument desc = invalid key access data",
		},
		{
			name: "Invalid JSON Format",
			inputJSON: []byte(`{
				"instance1": {
					"trustAnchorArn": "arn:aws:iam::123456789012:role/TrustAnchor",
					"profileArn": "arn:aws:iam::123456789012:role/Profile",
					"roleArn": "arn:aws:iam::123456789012:role/Role",
			}`), // Missing closing brace
			keyID:      "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr:    true,
			errMessage: "rpc error: code = InvalidArgument desc = invalid key access data",
		},
		{
			name: "Missing Required Field",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"instance1": {
						"trustAnchorArn": validTrustAnchorArnPrefix + "TrustAnchor1",
						"profileArn":     validProfileArnPrefix + "Profile1",
					},
				}
				bytes, _ := json.Marshal(data)
				return bytes
			}(),
			keyID:      "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr:    true,
			errMessage: "rpc error: code = InvalidArgument desc = invalid key access data",
		},
		{
			name: "Empty Instance Name",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"": {
						"trustAnchorArn": validTrustAnchorArnPrefix + "TrustAnchor1",
						"profileArn":     validProfileArnPrefix + "Profile1",
						"roleArn":        validRoleArnPrefix + "Role1",
					},
				}
				bytes, _ := json.Marshal(data)
				return bytes
			}(),
			keyID:      "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr:    true,
			errMessage: "rpc error: code = InvalidArgument desc = invalid key access data",
		},
		{
			name: "Empty Key ID",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"instance1": {
						"trustAnchorArn": validTrustAnchorArnPrefix + "TrustAnchor1",
						"profileArn":     validProfileArnPrefix + "Profile1",
						"roleArn":        validRoleArnPrefix + "Role1",
					},
				}
				bytes, _ := json.Marshal(data)
				return bytes
			}(),
			keyID:      "",
			wantErr:    true,
			errMessage: "AWS key ARN must be present in the keyID field of the request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			request := &operationsv1.TransformCryptoAccessDataRequest{
				NativeKeyId: tt.keyID,
				AccessData:  tt.inputJSON,
			}
			// Act
			resp, err := p.TransformCryptoAccessData(t.Context(), request)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMessage)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TransformedAccessData)
				for instance, data := range resp.TransformedAccessData {
					assert.NotEmpty(t, instance)
					assert.NotEmpty(t, data)
					var accessData protoDef.AWSKeyAccessData
					err := proto.Unmarshal(data, &accessData)
					assert.NoError(t, err)
					//nolint:staticcheck
					assert.Equal(t, tt.keyID, accessData.GetKeyArn())
					assert.NotEmpty(t, accessData.GetTrustAnchorArn())
					assert.NotEmpty(t, accessData.GetProfileArn())
					assert.NotEmpty(t, accessData.GetRoleArn())
					assert.Empty(t, accessData.GetCertificateSubject())
				}
			}
		})
	}
}

func TestTransformCryptoAccessDataWithCertificateSubject(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
		buildInfo,
	)

	certSubject := "CN=default.kms.aws,L=some-locality,OU=Platform Clients/dev/subaccount"

	inputJSON := func() []byte {
		data := map[string]map[string]interface{}{
			"instance1": {
				"trustAnchorArn":     validTrustAnchorArnPrefix + "TrustAnchor1",
				"profileArn":         validProfileArnPrefix + "Profile1",
				"roleArn":            validRoleArnPrefix + "Role1",
				"certificateSubject": certSubject,
			},
		}
		bytes, _ := json.Marshal(data)
		return bytes
	}()

	request := &operationsv1.TransformCryptoAccessDataRequest{
		NativeKeyId: "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
		AccessData:  inputJSON,
	}

	resp, err := p.TransformCryptoAccessData(t.Context(), request)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.TransformedAccessData)

	for instance, data := range resp.TransformedAccessData {
		assert.NotEmpty(t, instance)
		assert.NotEmpty(t, data)
		var accessData protoDef.AWSKeyAccessData
		err := proto.Unmarshal(data, &accessData)
		assert.NoError(t, err)
		//nolint:staticcheck
		assert.Equal(t, request.NativeKeyId, accessData.GetKeyArn())
		assert.NotEmpty(t, accessData.GetTrustAnchorArn())
		assert.NotEmpty(t, accessData.GetProfileArn())
		assert.NotEmpty(t, accessData.GetRoleArn())
		assert.Equal(t, certSubject, accessData.GetCertificateSubject())
	}
}
