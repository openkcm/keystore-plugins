package main

import (
	"github.com/openkcm/plugin-sdk/pkg/plugin"

	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	aws_plugin "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws"
)

// main serves as the entry point for the AWSPlugin KMS plugin
func main() {
	awsPlugin := aws_plugin.NewAWSPlugin(aws_plugin.NewAWSClient)

	plugin.Serve(
		operationsv1.KeystoreInstanceKeyOperationPluginServer(awsPlugin),
		configv1.ConfigServiceServer(awsPlugin),
	)
}
