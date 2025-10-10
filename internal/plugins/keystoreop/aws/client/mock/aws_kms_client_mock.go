package mock

import (
	"context"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	transport "github.com/aws/smithy-go/endpoints"
)

type DescribeKeyFuncType func(ctx context.Context,
	params *kms.DescribeKeyInput,
	optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)

// Mock is a mock of the AWS KMS client.
type Mock struct {
	DescribeKeyFunc DescribeKeyFuncType
}

// NewMock creates a new instance of Mock.
func NewMock() *Mock {
	return &Mock{}
}

// DescribeKey calls DescribeKeyFunc if set, otherwise it panics.
func (m *Mock) DescribeKey(
	ctx context.Context,
	params *kms.DescribeKeyInput,
	optFns ...func(*kms.Options),
) (*kms.DescribeKeyOutput, error) {
	if m.DescribeKeyFunc != nil {
		return m.DescribeKeyFunc(ctx, params, optFns...)
	}

	panic("DescribeKeyFunc not implemented")
}

// WithDescribeKeyFunc sets the DescribeKeyFunc for the mock.
func (m *Mock) WithDescribeKeyFunc(f DescribeKeyFuncType) *Mock {
	m.DescribeKeyFunc = f

	return m
}

// HappyPathMock creates a new instance of Mock with all methods returning success.
func HappyPathMock(expectedKeyID string, expectedKeyArn string, _ time.Time) *Mock {
	return NewMock().
		WithDescribeKeyFunc(
			func(_ context.Context,
				_ *kms.DescribeKeyInput,
				_ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
				return &kms.DescribeKeyOutput{
					KeyMetadata: &types.KeyMetadata{
						Arn:      &expectedKeyArn,
						KeyId:    &expectedKeyID,
						KeyState: types.KeyStateEnabled,
						KeySpec:  types.KeySpecSymmetricDefault,
						KeyUsage: types.KeyUsageTypeEncryptDecrypt,
					}}, nil
			})
}

// ErrorMock creates a new instance of Mock with all methods returning an error.
func ErrorMock(errForced error) *Mock {
	return NewMock().
		WithDescribeKeyFunc(
			func(_ context.Context,
				_ *kms.DescribeKeyInput,
				_ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
				return nil, errForced
			})
}

// HTTPClient is a mock of the HTTPClient interface that implements the Do method.
type HTTPClient struct{}

func (c *HTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

// EndpointResolver is a mock of the EndpointResolver interface that implements the ResolveEndpoint method.
type EndpointResolver struct{}

func (c EndpointResolver) ResolveEndpoint(
	context.Context,
	kms.EndpointParameters,
) (transport.Endpoint, error) {
	return transport.Endpoint{}, nil
}

// CredentialsProvider is a mock of the CredentialsProvider interface that implements the Retrieve method.
type CredentialsProvider struct{}

// Retrieve returns mock credentials.
func (m *CredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "mockAccessKeyID",
		SecretAccessKey: "mockSecretAccessKey",
	}, nil
}
