package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	aws "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client/mock"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
)

var (
	key            = uuid.New().String()
	secret         = uuid.New().String()
	token          = uuid.New().String()
	region         = uuid.New().String()
	errForced      = errors.New("forced error")
	expectedKeyID  = uuid.New().String()
	now            = time.Now().UTC()
	expectedKeyArn = "arn:aws:kms:us-west-2:123456789012:key/" + expectedKeyID
	happyPathMock  = mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	errorMock      = mock.ErrorMock(errForced)
	baseEndpoint   = "https://kms.us-west-2.amazonaws.com"
)

func TestClient_GetNativeKey(t *testing.T) {
	tests := []struct {
		name       string
		client     aws.ExportedKmsClient
		keyID      string
		wantOutput *base.KeyOutput
		wantErr    error
	}{
		{
			name:   "GetNativeKey_Success",
			client: happyPathMock,
			keyID:  expectedKeyID,
			wantOutput: &base.KeyOutput{
				ID:           expectedKeyID,
				KeyAlgorithm: base.AES256,
				Usage:        string(types.KeyUsageTypeEncryptDecrypt),
				Status:       string(base.KeyStateEnabled),
			},
			wantErr: nil,
		},
		{
			name:       "GetNativeKey_MissingKeyID",
			client:     happyPathMock,
			keyID:      "",
			wantOutput: nil,
			wantErr:    aws.ErrMissingID,
		},
		{
			name:       "GetNativeKey_DescribeKeyError",
			client:     errorMock,
			keyID:      expectedKeyID,
			wantOutput: nil,
			wantErr:    aws.ErrDescribeKeyFailed,
		},
		{
			name: "GetNativeKey_UnsupportedKeySpec",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithDescribeKeyFunc(func(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return &kms.DescribeKeyOutput{
						KeyMetadata: &types.KeyMetadata{
							KeyUsage: types.KeyUsageTypeEncryptDecrypt,
							KeySpec:  types.KeySpec("unsupported"),
						},
					}, nil
				}),
			keyID:      expectedKeyID,
			wantOutput: nil,
			wantErr:    aws.ErrUnsupportedKeySpec,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)

			output, err := c.GetKey(context.TODO(), tt.keyID)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.wantOutput, output)
		})
	}
}

// Helper function to validate internal client and aws_options
func validateClient(
	t *testing.T,
	client *aws.Client,
	region, key, secret string,
	baseEndpoint ...*string,
) {
	t.Helper()

	assert.NotNil(t, client)

	internalClient := client.ExportInternalClientForTests(t)

	internalOptions := internalClient.Options()
	assert.Equal(t, region, internalOptions.Region)

	retrieve, err := internalOptions.Credentials.Retrieve(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, key, retrieve.AccessKeyID)
	assert.Equal(t, secret, retrieve.SecretAccessKey)

	if len(baseEndpoint) > 0 && baseEndpoint[0] != nil {
		assert.Equal(t, baseEndpoint[0], internalOptions.BaseEndpoint)
	}
}

// TestNewClientWithOptions tests the NewClientWithOptions function to ensure it creates a valid KMS client.
func TestNewClientWithOptions(t *testing.T) {
	ctx := context.Background()
	credentialsProvider := credentials.NewStaticCredentialsProvider(key, secret, token)

	client := aws.NewClientWithOptions(
		ctx,
		region,
		credentialsProvider,
		aws.BaseEndpoint(baseEndpoint),
	)

	validateClient(t, client, region, key, secret, &baseEndpoint)
}

// TestNewClient tests the NewClient function to ensure it creates a valid KMS client with static credentials.
func TestNewClient(t *testing.T) {
	ctx := context.Background()

	client := aws.NewClient(ctx, region, key, secret)

	validateClient(t, client, region, key, secret)
}

// TestNewClientFromCredentialsProvider tests the NewClientFromCredentialsProvider
// function to ensure it creates a valid KMS client from a credentials providers.
func TestNewClientFromCredentialsProvider(t *testing.T) {
	ctx := context.Background()
	credentialsProvider := credentials.NewStaticCredentialsProvider(key, secret, token)

	client := aws.NewClientFromCredentialsProvider(ctx, region, credentialsProvider)

	validateClient(t, client, region, key, secret)
}

// TestNewBaseEndpointClient tests the NewBaseEndpointClient
// function to ensure it creates a valid KMS client with a base endpoint.
func TestNewBaseEndpointClient(t *testing.T) {
	ctx := context.Background()

	client := aws.NewBaseEndpointClient(ctx, region, baseEndpoint)

	validateClient(t, client, region, "dummy", "dummy", &baseEndpoint)
}

func TestConvertKeySpecToKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		keySpec   types.KeySpec
		expected  base.KeyAlgorithm
		expectErr bool
	}{
		{
			name:      "SymmetricDefault",
			keySpec:   types.KeySpecSymmetricDefault,
			expected:  base.AES256,
			expectErr: false,
		},
		{
			name:      "RSA3072",
			keySpec:   types.KeySpecRsa3072,
			expected:  base.RSA3072,
			expectErr: false,
		},
		{
			name:      "RSA4096",
			keySpec:   types.KeySpecRsa4096,
			expected:  base.RSA4096,
			expectErr: false,
		},
		{
			name:      "UnsupportedKeySpec",
			keySpec:   types.KeySpec("unsupported"),
			expected:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := aws.ConvertKeySpecToKeyAlgorithm(tt.keySpec)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestConvertKeyStateToBaseKeyState(t *testing.T) {
	tests := []struct {
		name     string
		input    types.KeyState
		expected base.KeyState
	}{
		{
			name:     "KeyStateEnabled",
			input:    types.KeyStateEnabled,
			expected: base.KeyStateEnabled,
		},
		{
			name:     "KeyStateDisabled",
			input:    types.KeyStateDisabled,
			expected: base.KeyStateDisabled,
		},
		{
			name:     "KeyStatePendingDeletion",
			input:    types.KeyStatePendingDeletion,
			expected: base.KeyStatePendingDeletion,
		},
		{
			name:     "KeyStatePendingImport",
			input:    types.KeyStatePendingImport,
			expected: base.KeyStatePendingImport,
		},
		{
			name:     "UnknownKeyState",
			input:    types.KeyState("UNKNOWN_STATE"),
			expected: base.KeyStateUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := aws.ConvertKeyStateToBaseKeyState(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertWrappingAlgorithmToBaseWrappingAlgorithmAndHash(t *testing.T) {
	tests := []struct {
		name        string
		input       types.AlgorithmSpec
		wantWrapAlg base.WrappingAlgorithm
		wantHash    base.HashFunction
		wantErr     bool
	}{
		{
			name:        "RSAES_OAEP_SHA_256",
			input:       types.AlgorithmSpecRsaesOaepSha256,
			wantWrapAlg: base.WrappingAlgorithmCKMRSAPKCSOAEP,
			wantHash:    base.HashFunctionSHA256,
			wantErr:     false,
		},
		{
			name:        "RSA_AES_KEY_WRAP_SHA_256",
			input:       types.AlgorithmSpecRsaAesKeyWrapSha256,
			wantWrapAlg: base.WrappingAlgorithmCKMRSAAESKEYWRAP,
			wantHash:    base.HashFunctionSHA256,
			wantErr:     false,
		},
		{
			name:        "UnsupportedAlgorithm",
			input:       types.AlgorithmSpec("UNSUPPORTED"),
			wantWrapAlg: "",
			wantHash:    "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapAlg, hash, err := aws.ConvertToBaseWrapAlgAndHash(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantWrapAlg, wrapAlg)
				assert.Equal(t, tt.wantHash, hash)
			}
		})
	}
}
