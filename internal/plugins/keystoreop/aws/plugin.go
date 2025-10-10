package aws

import (
	"context"
	"log/slog"

	"github.com/hashicorp/go-hclog"
	"github.com/openkcm/plugin-sdk/pkg/hclog2slog"

	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	aws "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
)

// AWSPlugin implements the KeystoreInstanceKeyOperationServer for AWSPlugin KMS
type AWSPlugin struct {
	operationsv1.UnsafeKeystoreInstanceKeyOperationServer
	configv1.UnsafeConfigServer

	clientFactory func(
		ctx context.Context,
		config *kscommonv1.KeystoreInstanceConfig,
		region string) (*aws.Client, error)
}

// Compiler check KeystoreInstanceKeyOperationServer interface properly implementated
var _ operationsv1.KeystoreInstanceKeyOperationServer = (*AWSPlugin)(nil)

// NewAWSPlugin creates a new AWSPlugin instance
func NewAWSPlugin(
	clientFactory func(
		ctx context.Context,
		config *kscommonv1.KeystoreInstanceConfig,
		region string) (*aws.Client, error),
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
	slog.SetDefault(hclog2slog.New(logger))
}
