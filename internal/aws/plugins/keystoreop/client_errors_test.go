package aws_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"

	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/internal/aws/plugins/keystoreop/mock"
)

func operationError(code string) error {
	return &smithy.OperationError{
		ServiceID:     "KMS",
		OperationName: "test",
		Err:           &smithy.GenericAPIError{Code: code, Message: "message"},
	}
}

func TestClient_GetKey_APIErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{"AccessDenied", operationError("AccessDeniedException"), aws.ErrAccessDenied},
		{"OtherAPIError", operationError("KMSInternalException"), aws.ErrDescribeKeyFailed},
		{
			"OperationErrorWithoutAPIError",
			&smithy.OperationError{ServiceID: "KMS", OperationName: "DescribeKey", Err: errForced},
			aws.ErrDescribeKeyFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).WithDescribeKeyFunc(
				func(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return nil, tt.err
				})

			out, err := aws.NewClientForTests(client).GetKey(t.Context(), expectedKeyID)

			assert.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, out)
		})
	}
}

func TestClient_GetKeyVersions_APIErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{"AccessDenied", operationError("AccessDeniedException"), aws.ErrAccessDenied},
		{"OtherAPIError", operationError("KMSInternalException"), aws.ErrListKeyRotationsFailed},
		{"NonAPIError", errForced, aws.ErrListKeyRotationsFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := mock.HappyPathMock(expectedKeyID, expectedKeyArn, now).WithListKeyRotationsFunc(
				func(context.Context, *kms.ListKeyRotationsInput, ...func(*kms.Options)) (*kms.ListKeyRotationsOutput, error) {
					return nil, tt.err
				})

			versions, err := aws.NewClientForTests(client).GetKeyVerions(t.Context(), expectedKeyID)

			assert.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, versions)
		})
	}
}
