package main_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"

	ap "github.com/openkcm/keystore-plugins/cmd/keystoreop/aws"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/base"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/clients/aws"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/clients/aws/mock"
	protoDef "github.com/openkcm/keystore-plugins/pkg/proto"
	"github.com/openkcm/keystore-plugins/utils/ptr"
)

const (
	keyId        = "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef"
	invalidKeyID = "invalid-key-id"
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
		name    string
		client  *mock.Mock
		req     *operationsv1.GetKeyRequest
		want    *operationsv1.GetKeyResponse
		wantErr bool
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
				Status:    string(base.KeyStateEnabled),
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
			)

			// Act
			resp, err := p.GetKey(context.Background(), tt.req)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)

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

func TestValidateKey(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
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
	)

	tests := []struct {
		name     string
		request  *operationsv1.ValidateKeyAccessDataRequest
		expected *operationsv1.ValidateKeyAccessDataResponse
	}{
		{
			name: "Valid Management and Crypto Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TrustAnchor"),
						"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/Profile"),
						"roleArn":        structpb.NewStringValue("arn:aws:iam::123456789012:role/Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TA1"),
								"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/P1"),
								"roleArn":        structpb.NewStringValue("arn:aws:iam::123456789012:role/R1"),
							},
						}),
						"instance2": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TA2"),
								"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/P2"),
								"roleArn":        structpb.NewStringValue("arn:aws:iam::123456789012:role/R2"),
							},
						}),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: true,
			},
		},
		{
			name: "Missing Management Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: nil,
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid AWS key management access data: invalid AWS key access data: missing trustAnchorArn",
			},
		},
		{
			name: "Invalid Crypto Data",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TrustAnchor"),
						"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/Profile"),
						"roleArn":        structpb.NewStringValue("arn:aws:iam::123456789012:role/Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStringValue("invalid-data"),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid data type for AWS crypto access data for instance: instance1",
			},
		},
		{
			name: "Empty Crypto Data for instance",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TrustAnchor"),
						"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/Profile"),
						"roleArn":        structpb.NewStringValue("arn:aws:iam::123456789012:role/Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewNullValue(),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "missing AWS crypto access data for instance: instance1",
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
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid AWS key management access data",
			},
		},
		{
			name: "Missing trustAnchorArn in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue(""),
						"profileArn":     structpb.NewStringValue("X"),
						"roleArn":        structpb.NewStringValue("Y"),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid AWS key management access data: invalid AWS key access data: missing trustAnchorArn",
			},
		},
		{
			name: "Missing profileArn in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("X"),
						"profileArn":     structpb.NewStringValue(""),
						"roleArn":        structpb.NewStringValue("Y"),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid AWS key management access data: invalid AWS key access data: missing profileArn",
			},
		},
		{
			name: "Missing roleArn in Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("X"),
						"profileArn":     structpb.NewStringValue("Y"),
						"roleArn":        structpb.NewStringValue(""),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid AWS key management access data: invalid AWS key access data: missing roleArn",
			},
		},
		{
			name: "Wrong data in Crypto",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TrustAnchor"),
						"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/Profile"),
						"roleArn":        structpb.NewStringValue("arn:aws:iam::123456789012:role/Role"),
					},
				},
				Crypto: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"instance1": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"trustAnchorArn": structpb.NewStringValue("arn:aws:iam::123456789012:role/TA1"),
								"profileArn":     structpb.NewStringValue("arn:aws:iam::123456789012:role/P1"),
								"accessKeyId":    structpb.NewStringValue("ABCD"),
							},
						}),
					},
				},
			},
			expected: &operationsv1.ValidateKeyAccessDataResponse{
				IsValid: false,
				Message: "invalid AWS key access data for instance instance1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, _ := p.ValidateKeyAccessData(context.Background(), tt.request)
			assert.Equal(t, tt.expected.IsValid, response.IsValid)
			assert.Contains(t, response.Message, tt.expected.Message)
		})
	}
}

func TestExtractKeyRegion(t *testing.T) {
	client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(client), nil
		},
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
						"trustAnchorArn": "arn:aws:iam::123456789012:role/TrustAnchor1",
						"profileArn":     "arn:aws:iam::123456789012:role/Profile1",
						"roleArn":        "arn:aws:iam::123456789012:role/Role1",
					},
					"instance2": {
						"trustAnchorArn": "arn:aws:iam::123456789012:role/TrustAnchor2",
						"profileArn":     "arn:aws:iam::123456789012:role/Profile2",
						"roleArn":        "arn:aws:iam::123456789012:role/Role2",
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
			errMessage: "failed to unmarshal crypto access data",
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
			errMessage: "failed to unmarshal crypto access data",
		},
		{
			name: "Missing Required Field",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"instance1": {
						"profileArn": "arn:aws:iam::123456789012:role/Profile",
						"roleArn":    "arn:aws:iam::123456789012:role/Role",
					},
				}
				bytes, _ := json.Marshal(data)
				return bytes
			}(),
			keyID:      "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr:    true,
			errMessage: "missing trustAnchorArn",
		},
		{
			name: "Empty Instance Name",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"": {
						"trustAnchorArn": "arn:aws:iam::123456789012:role/TrustAnchor",
						"profileArn":     "arn:aws:iam::123456789012:role/Profile",
						"roleArn":        "arn:aws:iam::123456789012:role/Role",
					},
				}
				bytes, _ := json.Marshal(data)
				return bytes
			}(),
			keyID:      "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef",
			wantErr:    true,
			errMessage: "instance name cannot be empty",
		},
		{
			name: "Empty Key ID",
			inputJSON: func() []byte {
				data := map[string]map[string]interface{}{
					"instance1": {
						"trustAnchorArn": "arn:aws:iam::123456789012:role/TrustAnchor",
						"profileArn":     "arn:aws:iam::123456789012:role/Profile",
						"roleArn":        "arn:aws:iam::123456789012:role/Role",
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
					assert.Equal(t, tt.keyID, accessData.GetKeyArn())
					assert.NotEmpty(t, accessData.GetTrustAnchorArn())
					assert.NotEmpty(t, accessData.GetProfileArn())
					assert.NotEmpty(t, accessData.GetRoleArn())
				}
			}
		})
	}
}
