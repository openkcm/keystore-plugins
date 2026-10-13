package main

import (
	"context"

	awsauth "github.com/openkcm/internal/aws/auth"
	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/internal/common"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
)

// NewAWSClient creates and returns an AWS client using the provided configuration
func NewAWSClient(
	ctx context.Context,
	config *kscommonv1.KeystoreInstanceConfig,
	region string,
) (*aws.Client, error) {
	if config == nil || config.Values == nil {
		return nil, common.ErrNilConfig
	}

	awsConfig, err := awsauth.GetCredentialsFromStruct(ctx, config.Values)
	if err != nil {
		return nil, err
	}

	sessionToken := ""
	if awsConfig.SessionToken != nil {
		sessionToken = *awsConfig.SessionToken
	}

	return aws.NewClient(
		ctx,
		region,
		awsConfig.AccessKeyID,
		awsConfig.SecretAccessKey,
		sessionToken,
	), nil
}
