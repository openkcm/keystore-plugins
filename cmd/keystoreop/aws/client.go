package main

import (
	"context"
	"errors"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	awsauth "github.com/openkcm/internal/aws/auth"
	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
)

// ClientFactory creates an AWS KMS client for a region from resolved credentials.
type ClientFactory = func(ctx context.Context, region string, creds awssdk.CredentialsProvider) (*aws.Client, error)

// NewAWSClient creates an AWS KMS client for region using creds.
func NewAWSClient(ctx context.Context, region string, creds awssdk.CredentialsProvider) (*aws.Client, error) {
	return aws.NewClientFromCredentialsProvider(ctx, region, creds), nil
}

// newClient resolves credentials with the configured authentication method
// and creates a client for region. Authentication failures are returned as
// gRPC provider authentication errors.
func (ap *AWSPlugin) newClient(
	ctx context.Context,
	config *kscommonv1.KeystoreInstanceConfig,
	region string,
) (*aws.Client, error) {
	ap.mu.RLock()
	credentials := ap.credentials
	ap.mu.RUnlock()

	creds, err := credentials.Credentials(ctx, awsauth.Request{Region: region, Values: config.GetValues()})
	if err != nil {
		return nil, ap.authenticationError(err)
	}

	client, err := ap.clientFactory(ctx, region, creds)
	if err != nil {
		return nil, ap.authenticationError(err)
	}

	return client, nil
}

// authenticationError converts a credentials error into a gRPC provider
// authentication error and returns any other error unchanged.
func (ap *AWSPlugin) authenticationError(err error) error {
	var reason string

	switch {
	case errors.Is(err, awsauth.ErrRoleNotAllowed):
		reason = GrpcErrorReasonRoleNotAllowed
	case errors.Is(err, awsauth.ErrCreateRolesAnywhereSession):
		reason = ap.mapRolesAnywhereErrorReason(err)
	case errors.Is(err, awsauth.ErrResolveCredentials):
		reason = GrpcErrorReasonGenericAuthError
	default:
		return err
	}

	return commonErrs.NewGrpcErrorWithDetails(commonErrs.StatusProviderAuthenticationError, reason, nil)
}
