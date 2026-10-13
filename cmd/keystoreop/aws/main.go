package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/hashicorp/go-hclog"
	"go.yaml.in/yaml/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/common-sdk/pkg/utils"
	awsauth "github.com/openkcm/internal/aws/auth"
	"github.com/openkcm/plugin-sdk/pkg/plugin"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"
)

var BuildInfo = "{}"

// AWSPlugin implements the KeystoreInstanceKeyOperationServer for AWSPlugin KMS
type AWSPlugin struct {
	operationsv1.UnsafeKeystoreInstanceKeyOperationServer
	configv1.UnsafeConfigServer

	logger        hclog.Logger
	clientFactory ClientFactory
	buildInfo     string

	mu          sync.RWMutex
	credentials awsauth.Source
}

// PluginConfig is the YAML configuration passed to Configure.
type PluginConfig struct {
	// Auth selects how the plugin authenticates with AWS. It is decoded
	// strictly by awsauth.DecodeConfig. When it is omitted, each request must
	// carry its own authType and credentials.
	Auth yaml.Node `yaml:"auth"`
}

// Compiler check KeystoreInstanceKeyOperationServer interface properly implementated
var _ operationsv1.KeystoreInstanceKeyOperationServer = (*AWSPlugin)(nil)

// NewAWSPlugin creates a new AWSPlugin instance. Until Configure selects an
// authentication method, credentials are read from each request.
func NewAWSPlugin(clientFactory ClientFactory, buildInfo string) *AWSPlugin {
	return &AWSPlugin{
		clientFactory: clientFactory,
		buildInfo:     buildInfo,
		credentials:   awsauth.NewPerRequestSource(),
	}
}

// Configure configures the plugin, selecting the AWS authentication method
// from the auth section of the configuration.
func (ap *AWSPlugin) Configure(
	ctx context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	var cfg PluginConfig

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), &cfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse plugin configuration: %v", err)
	}

	authCfg, err := awsauth.DecodeConfig(&cfg.Auth)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse auth configuration: %v", err)
	}

	credentials, err := awsauth.New(ctx, authCfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to configure AWS authentication: %v", err)
	}

	ap.mu.Lock()
	ap.credentials = credentials
	ap.mu.Unlock()

	if ap.logger != nil {
		ap.logger.Info("configured AWS authentication", "method", credentials.Method())
	}

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
