package aws_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/internal/aws/plugins/keystoreop/mock"
	"github.com/openkcm/internal/common/keystoreop"
	cryptoUtils "github.com/openkcm/utils/crypto"
	"github.com/openkcm/utils/ptr"
)

var (
	key                 = uuid.New().String()
	secret              = uuid.New().String()
	token               = uuid.New().String()
	region              = uuid.New().String()
	errForced           = errors.New("forced error")
	expectedID          = uuid.New().String()
	expectedKeyID       = uuid.New().String()
	now                 = time.Now().UTC()
	expectedKeyArn      = "arn:aws:kms:us-west-2:123456789012:key/" + expectedKeyID
	aliasName           = aws.PrepareAlias(expectedID)
	happyPathMock       = mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	errorMock           = mock.ErrorMock(errForced)
	baseEndpoint        = "https://kms.us-west-2.amazonaws.com"
	expectedImportToken = base64.StdEncoding.EncodeToString([]byte("mockedImportToken"))
	expectedPublicKey   = cryptoUtils.EncodeToPem([]byte("mockedPublicKey"), cryptoUtils.PEMArmorPublicKey)
	expectedValidTo     = now.Format(time.RFC3339)
)

// TestClient_CreateNativeKey tests the CreateKey function
func TestClient_CreateNativeKey(t *testing.T) {
	tests := []struct {
		name    string
		client  aws.ExportedKmsClient
		options keystoreop.KeyInput
		wantErr error
		wantArn *keystoreop.KeyOutput
	}{
		{
			name:    "CreateNativeKey_Success",
			client:  happyPathMock,
			options: keystoreop.KeyInput{ID: &expectedID, KeyAlgorithm: keystoreop.AES256, KeyType: keystoreop.KeyTypeSystemManaged},
			wantErr: nil,
			wantArn: &keystoreop.KeyOutput{ID: expectedKeyArn, Status: "ENABLED"},
		},
		{
			name:    "CreateNativeKey_MissingIDError",
			client:  happyPathMock,
			options: keystoreop.KeyInput{},
			wantErr: aws.ErrMissingID,
		},
		{
			name:    "CreateNativeKey_CreateKeyError",
			client:  errorMock,
			options: keystoreop.KeyInput{ID: &expectedID, KeyAlgorithm: keystoreop.AES256, KeyType: keystoreop.KeyTypeSystemManaged},
			wantErr: aws.ErrNativeCreateKeyFailed,
			wantArn: nil,
		},
		{
			name:    "CreateNativeKey_WrongKeyInputError",
			client:  happyPathMock,
			options: keystoreop.KeyInput{ID: &expectedID, KeyAlgorithm: "wrong", KeyType: keystoreop.KeyTypeSystemManaged},
			wantErr: aws.ErrNativeCreateKeyFailedWrongKeyInput,
			wantArn: nil,
		},
		{
			name: "CreateNativeKey_CreateAliasError",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).WithCreateAliasFunc(
				func(_ context.Context,
					_ *kms.CreateAliasInput,
					_ ...func(*kms.Options),
				) (*kms.CreateAliasOutput, error) {
					return nil, errForced
				},
			),
			options: keystoreop.KeyInput{ID: &expectedID, KeyAlgorithm: keystoreop.AES256, KeyType: keystoreop.KeyTypeSystemManaged},
			wantErr: aws.ErrNativeCreateAliasFailed,
			wantArn: nil,
		},
		{
			name: "CreateNativeKey_UpdateAliasError",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithCreateAliasFunc(
					func(_ context.Context,
						_ *kms.CreateAliasInput,
						_ ...func(*kms.Options),
					) (*kms.CreateAliasOutput, error) {
						return nil, &types.AlreadyExistsException{}
					}).
				WithUpdateAliasFunc(
					func(_ context.Context,
						_ *kms.UpdateAliasInput,
						_ ...func(*kms.Options),
					) (*kms.UpdateAliasOutput, error) {
						return nil, errForced
					}),
			options: keystoreop.KeyInput{ID: &expectedID, KeyAlgorithm: keystoreop.AES256, KeyType: keystoreop.KeyTypeSystemManaged},
			wantErr: aws.ErrNativeUpdateAliasFailed,
			wantArn: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)

			arn, err := c.CreateKey(context.TODO(), tt.options)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.wantArn, arn)
		})
	}
}

// testAlias is a helper function to test alias-related functions
func testAlias(
	t *testing.T,
	testName string,
	actionFunc func(c *aws.Client, aliasName, nativeKeyID string) error,
) {
	t.Helper()

	tests := []struct {
		name        string
		client      aws.ExportedKmsClient
		nativeKeyID string
		wantErr     error
	}{
		{
			name:        testName + "_Success",
			client:      happyPathMock,
			nativeKeyID: expectedKeyID,
			wantErr:     nil,
		},
		{
			name:        testName + "_Error",
			client:      errorMock,
			nativeKeyID: expectedKeyID,
			wantErr:     errForced,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)

			err := actionFunc(c, aliasName, tt.nativeKeyID)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// testFunction tests the native function
func testFunction(
	t *testing.T,
	testName string,
	actionFunc func(c *aws.Client, keyID string) error,
) {
	t.Helper()

	tests := []struct {
		name        string
		client      aws.ExportedKmsClient
		nativeKeyID string
		wantErr     error
	}{
		{
			name:        testName + "_Success",
			client:      happyPathMock,
			nativeKeyID: expectedKeyID,
			wantErr:     nil,
		},
		{
			name:        testName + "_Error",
			client:      errorMock,
			nativeKeyID: expectedKeyID,
			wantErr:     errForced,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)

			err := actionFunc(c, tt.nativeKeyID)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestClient_CreateNativeAlias tests the CreateNativeAlias function
func TestClient_CreateNativeAlias(t *testing.T) {
	testAlias(t, "CreateNativeAlias", func(c *aws.Client, aliasName, nativeKeyID string) error {
		return c.ExportCreateAlias()(context.TODO(), aliasName, nativeKeyID)
	})
}

// TestClient_UpdateNativeAlias tests the UpdateNativeAlias function
func TestClient_UpdateNativeAlias(t *testing.T) {
	testAlias(t, "UpdateNativeAlias", func(c *aws.Client, aliasName, nativeKeyID string) error {
		return c.ExportUpdateAlias()(context.TODO(), aliasName, nativeKeyID)
	})
}

// TestClient_EnsureAlias tests the EnsureAlias function
func TestClient_EnsureAlias(t *testing.T) {
	tests := []struct {
		name    string
		client  aws.ExportedKmsClient
		keyID   string
		id      string
		wantErr error
	}{
		{
			name:    "EnsureAlias_Success_CreateAlias",
			client:  happyPathMock,
			keyID:   expectedKeyID,
			id:      expectedID,
			wantErr: nil,
		},
		{
			name: "EnsureAlias_Success_UpdateAlias",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithCreateAliasFunc(
					func(_ context.Context,
						_ *kms.CreateAliasInput,
						_ ...func(*kms.Options),
					) (*kms.CreateAliasOutput, error) {
						return nil,
							&types.AlreadyExistsException{}
					}),
			keyID:   expectedKeyID,
			id:      expectedID,
			wantErr: nil,
		},
		{
			name: "EnsureAlias_Error_CreateAlias",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithCreateAliasFunc(
					func(_ context.Context,
						_ *kms.CreateAliasInput,
						_ ...func(*kms.Options),
					) (*kms.CreateAliasOutput, error) {
						return nil, errForced
					}),
			keyID:   expectedKeyID,
			id:      expectedID,
			wantErr: aws.ErrNativeCreateAliasFailed,
		},
		{
			name: "EnsureAlias_Error_UpdateAlias",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithCreateAliasFunc(
					func(_ context.Context,
						_ *kms.CreateAliasInput,
						_ ...func(*kms.Options),
					) (*kms.CreateAliasOutput, error) {
						return nil,
							&types.AlreadyExistsException{}
					}).
				WithUpdateAliasFunc(
					func(_ context.Context,
						_ *kms.UpdateAliasInput,
						_ ...func(*kms.Options),
					) (*kms.UpdateAliasOutput, error) {
						return nil, errForced
					}),
			keyID:   expectedKeyID,
			id:      expectedID,
			wantErr: aws.ErrNativeUpdateAliasFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)

			err := c.ExportEnsureAlias()(context.TODO(), tt.keyID, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetKeyVersions(t *testing.T) {
	t.Run("Should get versions ordered by newest", func(t *testing.T) {
		oldTime := now.Add(-24 * time.Hour)
		keyMaterialID := "mocked-key-material-id"
		oldKeyMaterialID := "old-key-material-id"
		client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).WithListKeyRotationsFunc(
			func(_ context.Context,
				_ *kms.ListKeyRotationsInput,
				_ ...func(*kms.Options),
			) (*kms.ListKeyRotationsOutput, error) {
				return &kms.ListKeyRotationsOutput{
					Rotations: []types.RotationsListEntry{
						{
							KeyId:            &expectedKeyID,
							KeyMaterialId:    &oldKeyMaterialID,
							KeyMaterialState: types.KeyMaterialStateNonCurrent,
							RotationDate:     &oldTime,
						},
						{
							KeyId:            &expectedKeyID,
							KeyMaterialId:    &keyMaterialID,
							KeyMaterialState: types.KeyMaterialStateCurrent,
							RotationDate:     &now,
						},
					},
				}, nil
			})
		c := aws.NewClientForTests(client)
		versions, err := c.GetKeyVerions(t.Context(), expectedKeyID)
		assert.NoError(t, err)
		assert.Len(t, versions, 2)
		assert.Equal(t, now, *versions[0].CreationTime)
		assert.Equal(t, oldTime, *versions[1].CreationTime)
		assert.Equal(t, keyMaterialID, versions[0].ID)
		assert.Equal(t, oldKeyMaterialID, versions[1].ID)
	})
}

func TestClient_GetNativeKey(t *testing.T) {
	tests := []struct {
		name       string
		client     aws.ExportedKmsClient
		keyID      string
		wantOutput *keystoreop.KeyOutput
		wantErr    error
	}{
		{
			name:   "GetNativeKey_Success",
			client: happyPathMock,
			keyID:  expectedKeyID,
			wantOutput: &keystoreop.KeyOutput{
				ID:               expectedKeyID,
				KeyAlgorithm:     keystoreop.AES256,
				Usage:            string(types.KeyUsageTypeEncryptDecrypt),
				Status:           string(keystoreop.KeyStateEnabled),
				CurrentVersionID: "mocked-key-material-id",
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
		{
			name: "GetNativeKey_StatusKeyNotFound",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithDescribeKeyFunc(
					func(
						_ context.Context,
						_ *kms.DescribeKeyInput,
						_ ...func(*kms.Options),
					) (*kms.DescribeKeyOutput, error) {
						return nil, &types.NotFoundException{}
					}),
			keyID:      expectedKeyID,
			wantOutput: nil,
			wantErr:    aws.ErrNativeKeyNotFound,
		},
		{
			name: "GetNativeKey_NoRotations",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithListKeyRotationsFunc(
					func(_ context.Context,
						_ *kms.ListKeyRotationsInput,
						_ ...func(*kms.Options),
					) (*kms.ListKeyRotationsOutput, error) {
						return &kms.ListKeyRotationsOutput{
							Rotations: []types.RotationsListEntry{},
						}, nil
					}),
			keyID: expectedKeyID,
			wantOutput: &keystoreop.KeyOutput{
				ID:               expectedKeyID,
				KeyAlgorithm:     keystoreop.AES256,
				Usage:            string(types.KeyUsageTypeEncryptDecrypt),
				Status:           string(keystoreop.KeyStateEnabled),
				RotationTime:     nil,
				CurrentVersionID: "mocked-key-material-id",
			},
			wantErr: nil,
		},
		{
			name: "GetNativeKey_ListRotationsError",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithListKeyRotationsFunc(
					func(_ context.Context,
						_ *kms.ListKeyRotationsInput,
						_ ...func(*kms.Options),
					) (*kms.ListKeyRotationsOutput, error) {
						return nil, errForced
					}),
			keyID: expectedKeyID,
			wantOutput: &keystoreop.KeyOutput{
				ID:               expectedKeyID,
				KeyAlgorithm:     keystoreop.AES256,
				Usage:            string(types.KeyUsageTypeEncryptDecrypt),
				Status:           string(keystoreop.KeyStateEnabled),
				RotationTime:     nil, // Should be nil when ListKeyRotations fails
				CurrentVersionID: "mocked-key-material-id",
			},
			wantErr: nil,
		},
		{
			name: "GetNativeKey_RotationWithNilDate",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithListKeyRotationsFunc(
					func(_ context.Context,
						_ *kms.ListKeyRotationsInput,
						_ ...func(*kms.Options),
					) (*kms.ListKeyRotationsOutput, error) {
						keyMaterialID := "mocked-key-material-id"
						return &kms.ListKeyRotationsOutput{
							Rotations: []types.RotationsListEntry{
								{
									KeyId:            &expectedKeyID,
									KeyMaterialId:    &keyMaterialID,
									KeyMaterialState: types.KeyMaterialStateCurrent,
									RotationDate:     nil, // nil date
								},
							},
						}, nil
					}),
			keyID: expectedKeyID,
			wantOutput: &keystoreop.KeyOutput{
				ID:               expectedKeyID,
				KeyAlgorithm:     keystoreop.AES256,
				Usage:            string(types.KeyUsageTypeEncryptDecrypt),
				Status:           string(keystoreop.KeyStateEnabled),
				RotationTime:     nil,
				CurrentVersionID: "mocked-key-material-id",
			},
			wantErr: nil,
		},
		{
			name: "GetNativeKey_MultipleRotations_OnlyCurrentReturned",
			client: mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).
				WithListKeyRotationsFunc(
					func(_ context.Context,
						_ *kms.ListKeyRotationsInput,
						_ ...func(*kms.Options),
					) (*kms.ListKeyRotationsOutput, error) {
						keyMaterialID := "mocked-key-material-id"
						oldKeyMaterialID := "old-key-material-id"
						oldTime := now.Add(-24 * time.Hour)
						return &kms.ListKeyRotationsOutput{
							Rotations: []types.RotationsListEntry{
								{
									KeyId:            &expectedKeyID,
									KeyMaterialId:    &oldKeyMaterialID,
									KeyMaterialState: types.KeyMaterialStateNonCurrent,
									RotationDate:     &oldTime,
								},
								{
									KeyId:            &expectedKeyID,
									KeyMaterialId:    &keyMaterialID,
									KeyMaterialState: types.KeyMaterialStateCurrent,
									RotationDate:     &now,
								},
							},
						}, nil
					}),
			keyID: expectedKeyID,
			wantOutput: &keystoreop.KeyOutput{
				ID:               expectedKeyID,
				KeyAlgorithm:     keystoreop.AES256,
				Usage:            string(types.KeyUsageTypeEncryptDecrypt),
				Status:           string(keystoreop.KeyStateEnabled),
				CurrentVersionID: "mocked-key-material-id",
			},
			wantErr: nil,
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

func TestClient_GetImportParameters(t *testing.T) {
	tests := []struct {
		name       string
		client     aws.ExportedKmsClient
		keyID      string
		algorithm  keystoreop.KeyAlgorithm
		wantOutput *keystoreop.GetImportParametersOutput
		wantErr    error
	}{
		{
			name:      "GetImportParameters_Success_AES256",
			client:    happyPathMock,
			keyID:     expectedKeyID,
			algorithm: keystoreop.AES256,
			wantOutput: &keystoreop.GetImportParametersOutput{
				ID:                expectedKeyID,
				ProviderParams:    expectedImportToken,
				PublicKey:         expectedPublicKey,
				ValidTo:           expectedValidTo,
				WrappingAlgorithm: string(keystoreop.WrappingAlgorithmCKMRSAPKCSOAEP),
				HashFunction:      string(keystoreop.HashFunctionSHA256),
			},
			wantErr: nil,
		},
		{
			name:      "GetImportParameters_Success_RSA3072",
			client:    happyPathMock,
			keyID:     expectedKeyID,
			algorithm: keystoreop.RSA3072,
			wantOutput: &keystoreop.GetImportParametersOutput{
				ID:                expectedKeyID,
				ProviderParams:    expectedImportToken,
				PublicKey:         expectedPublicKey,
				ValidTo:           expectedValidTo,
				WrappingAlgorithm: string(keystoreop.WrappingAlgorithmCKMRSAAESKEYWRAP),
				HashFunction:      string(keystoreop.HashFunctionSHA256),
			},
			wantErr: nil,
		},
		{
			name:      "GetImportParameters_Success_RSA4096",
			client:    happyPathMock,
			keyID:     expectedKeyID,
			algorithm: keystoreop.RSA4096,
			wantOutput: &keystoreop.GetImportParametersOutput{
				ID:                expectedKeyID,
				ProviderParams:    expectedImportToken,
				PublicKey:         expectedPublicKey,
				ValidTo:           expectedValidTo,
				WrappingAlgorithm: string(keystoreop.WrappingAlgorithmCKMRSAAESKEYWRAP),
				HashFunction:      string(keystoreop.HashFunctionSHA256),
			},
			wantErr: nil,
		},
		{
			name:       "GetImportParameters_MissingKeyID",
			client:     happyPathMock,
			keyID:      "",
			algorithm:  keystoreop.AES256,
			wantOutput: nil,
			wantErr:    aws.ErrMissingID,
		},
		{
			name:       "GetImportParameters_UnsupportedAlgorithm",
			client:     happyPathMock,
			keyID:      expectedKeyID,
			algorithm:  keystoreop.KeyAlgorithm("unsupported"),
			wantOutput: nil,
			wantErr:    aws.ErrUnsupportedKeySpec,
		},
		{
			name:       "GetImportParameters_ProviderError",
			client:     errorMock,
			keyID:      expectedKeyID,
			algorithm:  keystoreop.AES256,
			wantOutput: nil,
			wantErr:    aws.ErrGetImportParametersFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)

			output, err := c.GetImportParameters(context.TODO(), tt.keyID, tt.algorithm)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.wantOutput, output)
		})
	}
}

func TestClient_ImportKeyMaterial(t *testing.T) {
	tests := []struct {
		name                 string
		client               aws.ExportedKmsClient
		keyID                string
		importToken          []byte
		encryptedKeyMaterial []byte
		wantErr              error
	}{
		{
			name:                 "ImportKeyMaterial_Success",
			client:               happyPathMock,
			keyID:                expectedKeyID,
			importToken:          []byte("token"),
			encryptedKeyMaterial: []byte("material"),
			wantErr:              nil,
		},
		{
			name:                 "ImportKeyMaterial_MissingKeyID",
			client:               happyPathMock,
			keyID:                "",
			importToken:          []byte("token"),
			encryptedKeyMaterial: []byte("material"),
			wantErr:              aws.ErrMissingID,
		},
		{
			name:                 "ImportKeyMaterial_ProviderError",
			client:               errorMock,
			keyID:                expectedKeyID,
			importToken:          []byte("token"),
			encryptedKeyMaterial: []byte("material"),
			wantErr:              aws.ErrImportKeyMaterialFailed,
		},
		{
			name:  "ImportKeyMaterial_InvalidCiphertext",
			keyID: expectedKeyID,
			client: mock.NewMock().WithImportKeyMaterialFunc(
				func(_ context.Context, _ *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
					return nil, &types.InvalidCiphertextException{Message: ptr.PointTo("decryption failed")}
				}),
			importToken:          []byte("token"),
			encryptedKeyMaterial: []byte("material"),
			wantErr:              aws.ErrInvalidKeyMaterial,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := aws.NewClientForTests(tt.client)
			err := c.ImportKeyMaterial(context.TODO(), tt.keyID, tt.importToken, tt.encryptedKeyMaterial)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestClient_EnableNative tests the EnableKey function
func TestClient_EnableNative(t *testing.T) {
	testFunction(t, "EnableKey", func(c *aws.Client, keyID string) error {
		return c.EnableKey(context.TODO(), keyID)
	})
}

// TestClient_DisableNative tests the DisableKey function
func TestClient_DisableNative(t *testing.T) {
	testFunction(t, "DisableKey", func(c *aws.Client, keyID string) error {
		return c.DisableKey(context.TODO(), keyID)
	})
}

// TestClient_DeleteNative tests the DeleteKey function
func TestClient_DeleteNative(t *testing.T) {
	testFunction(t, "DeleteKey", func(c *aws.Client, keyID string) error {
		return c.DeleteKey(context.TODO(), keyID, keystoreop.DeleteOptions{})
	})
}

// TestCreateKeyInputFromKeyOptions tests the createKeyInputFromKeyOptions function
func TestCreateKeyInputFromKeyOptions(t *testing.T) {
	tests := []struct {
		name    string
		options keystoreop.KeyInput
		want    *kms.CreateKeyInput
		wantErr error
	}{
		{
			name:    "CreateKeyInputFromKeyOptions_AES256_AWS",
			options: keystoreop.KeyInput{KeyAlgorithm: keystoreop.AES256, KeyType: keystoreop.KeyTypeSystemManaged},
			want: &kms.CreateKeyInput{
				KeySpec:  types.KeySpecSymmetricDefault,
				KeyUsage: types.KeyUsageTypeEncryptDecrypt,
				Origin:   types.OriginTypeAwsKms,
			},
			wantErr: nil,
		},
		{
			name:    "CreateKeyInputFromKeyOptions_RSA3072_AWS",
			options: keystoreop.KeyInput{KeyAlgorithm: keystoreop.RSA3072, KeyType: keystoreop.KeyTypeSystemManaged},
			want: &kms.CreateKeyInput{
				KeySpec:  types.KeySpecRsa3072,
				KeyUsage: types.KeyUsageTypeEncryptDecrypt,
				Origin:   types.OriginTypeAwsKms,
			},
			wantErr: nil,
		},
		{
			name:    "CreateKeyInputFromKeyOptions_RSA4096_AWS",
			options: keystoreop.KeyInput{KeyAlgorithm: keystoreop.RSA4096, KeyType: keystoreop.KeyTypeSystemManaged},
			want: &kms.CreateKeyInput{
				KeySpec:  types.KeySpecRsa4096,
				KeyUsage: types.KeyUsageTypeEncryptDecrypt,
				Origin:   types.OriginTypeAwsKms,
			},
			wantErr: nil,
		},
		{
			name:    "CreateKeyInputFromKeyOptions_AES256_EXTERNAL",
			options: keystoreop.KeyInput{KeyAlgorithm: keystoreop.AES256, KeyType: keystoreop.KeyTypeBYOK},
			want: &kms.CreateKeyInput{
				KeySpec:  types.KeySpecSymmetricDefault,
				KeyUsage: types.KeyUsageTypeEncryptDecrypt,
				Origin:   types.OriginTypeExternal,
			},
			wantErr: nil,
		},
		{
			name:    "CreateKeyInputFromKeyOptions_RSA3072_EXTERNAL",
			options: keystoreop.KeyInput{KeyAlgorithm: keystoreop.RSA3072, KeyType: keystoreop.KeyTypeBYOK},
			want: &kms.CreateKeyInput{
				KeySpec:  types.KeySpecRsa3072,
				KeyUsage: types.KeyUsageTypeEncryptDecrypt,
				Origin:   types.OriginTypeExternal,
			},
			wantErr: nil,
		},
		{
			name:    "CreateKeyInputFromKeyOptions_RSA4096_EXTERNAL",
			options: keystoreop.KeyInput{KeyAlgorithm: keystoreop.RSA4096, KeyType: keystoreop.KeyTypeBYOK},
			want: &kms.CreateKeyInput{
				KeySpec:  types.KeySpecRsa4096,
				KeyUsage: types.KeyUsageTypeEncryptDecrypt,
				Origin:   types.OriginTypeExternal,
			},
			wantErr: nil,
		},
		{
			name:    "CreateKeyInputFromKeyOptions_UnknownKeyType",
			options: keystoreop.KeyInput{KeyAlgorithm: "unknown"},
			want:    nil,
			wantErr: fmt.Errorf("%w: %v", aws.ErrUnknownOptionType, "unknown"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := aws.CreateKeyInputFromKeyOptions(tt.options)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.want, result)
		})
	}
}

// TestCreateKeyFromCreateKeyOutput tests the CreateKeyFromCreateKeyOutput function
func TestCreateScheduleKeyDeletionInputFromDeleteOptions(t *testing.T) {
	tests := []struct {
		name    string
		keyID   string
		options keystoreop.DeleteOptions
		want    *kms.ScheduleKeyDeletionInput
	}{
		{
			name:  "CreateScheduleKeyDeletionInput_WindowSet",
			keyID: expectedKeyID,
			options: keystoreop.DeleteOptions{
				Window: ptr.PointTo(int32(7)),
			},
			want: &kms.ScheduleKeyDeletionInput{
				KeyId:               &expectedKeyID,
				PendingWindowInDays: ptr.PointTo(int32(7)),
			},
		},
		{
			name:    "CreateScheduleKeyDeletionInput_WindowNotSet",
			keyID:   expectedKeyID,
			options: keystoreop.DeleteOptions{},
			want: &kms.ScheduleKeyDeletionInput{
				KeyId: &expectedKeyID,
			},
		},
		{
			name:    "CreateScheduleKeyDeletionInput_OptionsNil",
			keyID:   expectedKeyID,
			options: keystoreop.DeleteOptions{},
			want: &kms.ScheduleKeyDeletionInput{
				KeyId: &expectedKeyID,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := aws.CreateScheduleKeyDeletionInputFromDeleteOptions(tt.keyID, tt.options)
			assert.Equal(t, tt.want, result)
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

func TestConvertKeySpecToKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		keySpec   types.KeySpec
		expected  keystoreop.KeyAlgorithm
		expectErr bool
	}{
		{
			name:      "SymmetricDefault",
			keySpec:   types.KeySpecSymmetricDefault,
			expected:  keystoreop.AES256,
			expectErr: false,
		},
		{
			name:      "RSA3072",
			keySpec:   types.KeySpecRsa3072,
			expected:  keystoreop.RSA3072,
			expectErr: false,
		},
		{
			name:      "RSA4096",
			keySpec:   types.KeySpecRsa4096,
			expected:  keystoreop.RSA4096,
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
		expected keystoreop.KeyState
	}{
		{
			name:     "KeyStateEnabled",
			input:    types.KeyStateEnabled,
			expected: keystoreop.KeyStateEnabled,
		},
		{
			name:     "KeyStateDisabled",
			input:    types.KeyStateDisabled,
			expected: keystoreop.KeyStateDisabled,
		},
		{
			name:     "KeyStatePendingDeletion",
			input:    types.KeyStatePendingDeletion,
			expected: keystoreop.KeyStatePendingDeletion,
		},
		{
			name:     "KeyStatePendingImport",
			input:    types.KeyStatePendingImport,
			expected: keystoreop.KeyStatePendingImport,
		},
		{
			name:     "UnknownKeyState",
			input:    types.KeyState("UNKNOWN_STATE"),
			expected: keystoreop.KeyStateUnknown,
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
		wantWrapAlg keystoreop.WrappingAlgorithm
		wantHash    keystoreop.HashFunction
		wantErr     bool
	}{
		{
			name:        "RSAES_OAEP_SHA_256",
			input:       types.AlgorithmSpecRsaesOaepSha256,
			wantWrapAlg: keystoreop.WrappingAlgorithmCKMRSAPKCSOAEP,
			wantHash:    keystoreop.HashFunctionSHA256,
			wantErr:     false,
		},
		{
			name:        "RSA_AES_KEY_WRAP_SHA_256",
			input:       types.AlgorithmSpecRsaAesKeyWrapSha256,
			wantWrapAlg: keystoreop.WrappingAlgorithmCKMRSAAESKEYWRAP,
			wantHash:    keystoreop.HashFunctionSHA256,
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
