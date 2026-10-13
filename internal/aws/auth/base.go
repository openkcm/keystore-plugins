package auth

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// baseSource serves MethodAmbient and MethodAccessKey: one set of
// credentials shared by every request.
type baseSource struct {
	kind  Method
	creds aws.CredentialsProvider
}

func newBaseSource(ctx context.Context, method Method, accessKey *AccessKeyConfig, deps dependencies) (*baseSource, error) {
	creds, err := baseCredentials(ctx, method, accessKey, deps)
	if err != nil {
		return nil, err
	}

	return &baseSource{kind: method, creds: creds}, nil
}

func (s *baseSource) method() Method {
	return s.kind
}

func (s *baseSource) provider(context.Context, Request) (aws.CredentialsProvider, error) {
	return s.creds, nil
}

// baseCredentials builds the ambient or access key credentials provider.
func baseCredentials(
	ctx context.Context,
	method Method,
	accessKey *AccessKeyConfig,
	deps dependencies,
) (aws.CredentialsProvider, error) {
	if method == MethodAccessKey {
		return accessKeyCredentials(accessKey)
	}

	cfg, err := deps.loadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: loading default credential chain: %w", ErrInvalidAuthConfig, err)
	}

	return cfg.Credentials, nil
}

func accessKeyCredentials(cfg *AccessKeyConfig) (aws.CredentialsProvider, error) {
	accessKeyID, err := loadSourceRef("accessKey.accessKeyId", cfg.AccessKeyID)
	if err != nil {
		return nil, err
	}

	secretAccessKey, err := loadSourceRef("accessKey.secretAccessKey", cfg.SecretAccessKey)
	if err != nil {
		return nil, err
	}

	sessionToken, err := loadOptionalSourceRef("accessKey.sessionToken", cfg.SessionToken)
	if err != nil {
		return nil, err
	}

	return credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken), nil
}
