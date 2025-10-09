package aws

import (
	"context"

	"github.com/hashicorp/go-hclog"

	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	aws_client "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
)

// AWSPlugin implements the KeystoreInstanceKeyOperationServer for AWSPlugin KMS
type AWSPlugin struct {
	operationsv1.UnsafeKeystoreInstanceKeyOperationServer
	configv1.UnsafeConfigServer

	logger        hclog.Logger
	clientFactory func(
		ctx context.Context,
		config *kscommonv1.KeystoreInstanceConfig,
		region string) (*aws_client.Client, error)
}

// Compiler check KeystoreInstanceKeyOperationServer interface properly implementated
var _ operationsv1.KeystoreInstanceKeyOperationServer = (*AWSPlugin)(nil)

// NewAWSPlugin creates a new AWSPlugin instance
func NewAWSPlugin(
	clientFactory func(
		ctx context.Context,
		config *kscommonv1.KeystoreInstanceConfig,
		region string) (*aws_client.Client, error),
) *AWSPlugin {
	return &AWSPlugin{
		clientFactory: clientFactory,
	}
}

// Configure configures the plugin
func (ap *AWSPlugin) Configure(
	_ context.Context,
	_ *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	return &configv1.ConfigureResponse{}, nil
}

func (ap *AWSPlugin) SetLogger(logger hclog.Logger) {
	ap.logger = logger
}
