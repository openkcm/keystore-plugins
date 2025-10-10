package aws_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"

	aws_keystore "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws"
	aws "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client/mock"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
	protoDef "github.com/openkcm/keystore-plugins/pkg/proto"
)

const keyId = "arn:aws:kms:us-west-2:123456789012:key/12345678-90ab-cdef-1234-567890abcdef"

// --- Helpers ---

func newPlugin(client *mock.Mock) *aws_keystore.AWSPlugin {
	return aws_keystore.NewAWSPlugin(func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
		return aws.NewClientForTests(client), nil
	})
}

func newConfig(t *testing.T, values map[string]interface{}) *kscommonv1.KeystoreInstanceConfig {
	t.Helper()

	anyConfig, err := structpb.NewStruct(values)
	assert.NoError(t, err)

	return &kscommonv1.KeystoreInstanceConfig{Values: anyConfig}
}

// --- Tests ---

func TestAWSGetKey(t *testing.T) {
	tests := []struct {
		name    string
		client  *mock.Mock
		req     *operationsv1.GetKeyRequest
		want    *operationsv1.GetKeyResponse
		wantErr bool
	}{
		{
			name:   "Success",
			client: mock.HappyPathMock(keyId, keyId, time.Now()),
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: keyId},
			},
			want: &operationsv1.GetKeyResponse{
				KeyId:     keyId,
				Algorithm: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
				Status:    string(base.KeyStateEnabled),
				Usage:     "ENCRYPT_DECRYPT",
			},
		},
		{
			name:   "Error_InvalidKeyID",
			client: mock.HappyPathMock(keyId, keyId, time.Now()),
			req: &operationsv1.GetKeyRequest{
				Parameters: &operationsv1.RequestParameters{KeyId: "invalid-key-id"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.req.Parameters.Config = newConfig(t, map[string]interface{}{
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
			})

			p := newPlugin(tt.client)
			resp, err := p.GetKey(context.Background(), tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, resp)
		})
	}
}

func TestExtractRegionFromARN(t *testing.T) {
	tests := []struct {
		arn     string
		want    string
		wantErr bool
	}{
		{keyId, "us-west-2", false},
		{"invalid-arn", "", true},
		{"arn:aws:kms::123456789012:key/abc", "", true},
		{"arn:aws:kms:us-west-2", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			got, err := aws_keystore.ExtractRegionFromARN(tt.arn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestValidateKeyAccessData(t *testing.T) {
	client := mock.HappyPathMock(keyId, keyId, time.Now())
	p := newPlugin(client)

	tests := []struct {
		name    string
		request *operationsv1.ValidateKeyAccessDataRequest
		isValid bool
		errMsg  string
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
			isValid: true,
		},
		{
			name: "Missing Management",
			request: &operationsv1.ValidateKeyAccessDataRequest{
				Management: nil,
			},
			isValid: false,
			errMsg:  "invalid AWS key management access data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := p.ValidateKeyAccessData(context.Background(), tt.request)
			assert.Equal(t, tt.isValid, resp.IsValid)

			if !tt.isValid {
				assert.Contains(t, resp.Message, tt.errMsg)
			}
		})
	}
}

func TestTransformCryptoAccessData(t *testing.T) {
	client := mock.HappyPathMock(keyId, keyId, time.Now())
	p := newPlugin(client)

	tests := []struct {
		name       string
		input      map[string]map[string]string
		keyID      string
		wantErr    bool
		errMessage string
	}{
		{
			name: "Valid Input",
			input: map[string]map[string]string{
				"instance1": {"trustAnchorArn": "ta1", "profileArn": "p1", "roleArn": "r1"},
				"instance2": {"trustAnchorArn": "ta2", "profileArn": "p2", "roleArn": "r2"},
			},
			keyID: keyId,
		},
		{
			name:    "Empty Input",
			input:   nil,
			keyID:   keyId,
			wantErr: false, // ✅ actual behavior: no error, returns empty map
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJSON, _ := json.Marshal(tt.input)
			req := &operationsv1.TransformCryptoAccessDataRequest{
				NativeKeyId: tt.keyID,
				AccessData:  inputJSON,
			}

			resp, err := p.TransformCryptoAccessData(context.Background(), req)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)

				if tt.errMessage != "" {
					assert.Contains(t, err.Error(), tt.errMessage)
				}

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			// Accept empty map for empty input
			assert.NotNil(t, resp.TransformedAccessData)

			for _, data := range resp.TransformedAccessData {
				var accessData protoDef.AWSKeyAccessData

				err := proto.Unmarshal(data, &accessData)
				assert.NoError(t, err)
			}
		})
	}
}
