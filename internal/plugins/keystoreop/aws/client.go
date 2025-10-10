package aws

import (
	"context"

	"google.golang.org/protobuf/types/known/structpb"

	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"

	"github.com/openkcm/keystore-plugins/internal/common"
	aws "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
)

// GetAWSConfig validates the provided configuration and returns an AWSConfig
func GetAWSConfig(ctx context.Context, config *structpb.Struct) (*common.AWSConfig, error) {
	reader, err := common.NewStructReader(config)
	if err != nil {
		return nil, err
	}

	// Determine auth type
	authType, err := reader.GetString("authType")
	if err != nil {
		return nil, err
	}

	// Create auth method based on type
	authMethod, err := AWSAuthFactory(authType)
	if err != nil {
		return nil, err
	}

	// Get credentials using the selected auth method
	return authMethod.GetCredentials(ctx, reader)
}

// NewAWSClient creates and returns an AWS client using the provided configuration
func NewAWSClient(
	ctx context.Context,
	config *kscommonv1.KeystoreInstanceConfig,
	region string,
) (*aws.Client, error) {
	if config == nil || config.Values == nil {
		return nil, common.ErrNilConfig
	}

	// Get AWS configuration
	awsConfig, err := GetAWSConfig(ctx, config.Values)
	if err != nil {
		return nil, err
	}

	// Default empty session token if not provided
	sessionToken := ""
	if awsConfig.SessionToken != nil {
		sessionToken = *awsConfig.SessionToken
	}

	// Create new AWS client with validated configuration
	client := aws.NewClient(
		ctx,
		region,
		awsConfig.AccessKeyID,
		awsConfig.SecretAccessKey,
		sessionToken,
	)

	return client, nil
}
