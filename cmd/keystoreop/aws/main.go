package main

import (
	"context"
	"log/slog"

	"github.com/hashicorp/go-hclog"

	"github.com/openkcm/common-sdk/pkg/utils"
	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/plugin-sdk/pkg/plugin"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"
)

var BuildInfo = "{}"

// AWSPlugin implements the KeystoreInstanceKeyOperationServer for AWSPlugin KMS
type AWSPlugin struct {
	operationsv1.UnsafeKeystoreInstanceKeyOperationServer
	configv1.UnsafeConfigServer
	logger        hclog.Logger
	clientFactory func(
		ctx context.Context,
		config *kscommonv1.KeystoreInstanceConfig,
		region string) (*aws.Client, error)
	buildInfo string
}

// Compiler check KeystoreInstanceKeyOperationServer interface properly implementated
var _ operationsv1.KeystoreInstanceKeyOperationServer = (*AWSPlugin)(nil)

// NewAWSPlugin creates a new AWSPlugin instance
func NewAWSPlugin(
	clientFactory func(
		ctx context.Context,
		config *kscommonv1.KeystoreInstanceConfig,
		region string) (*aws.Client, error),
	buildInfo string,
) *AWSPlugin {
	return &AWSPlugin{
		clientFactory: clientFactory,
		buildInfo:     buildInfo,
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

// main serves as the entry point for the AWSPlugin KMS plugin
func main() {
	value, err := utils.ExtractFromComplexValue(BuildInfo)
	if err != nil {
		slog.Warn("Failed to extract BuildInfo")
	}
	awsPlugin := NewAWSPlugin(NewAWSClient, value)

	plugin.Serve(
		operationsv1.KeystoreInstanceKeyOperationPluginServer(awsPlugin),
		configv1.ConfigServiceServer(awsPlugin),
	)
}
