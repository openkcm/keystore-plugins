package main_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	commonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"

	aws "github.com/openkcm/keystore-plugins/cmd/keystoreop/aws"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/base"
)

func TestGetClient(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]interface{}
		expectErr bool
	}{
		{
			name: "valid SECRET config",
			config: map[string]interface{}{
				"authType":        base.AuthTypeSecret,
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
			},
			expectErr: false,
		},
		{
			name: "valid SECRET config with session token",
			config: map[string]interface{}{
				"authType":        base.AuthTypeSecret,
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
				"sessionToken":    "test-session-token",
			},
			expectErr: false,
		},
		{
			name:      "invalid config",
			config:    map[string]interface{}{},
			expectErr: true,
		},
		{
			name:      "nil config",
			config:    nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			structConfig, err := func() (*structpb.Struct, error) {
				if tt.config != nil {
					return structpb.NewStruct(tt.config)
				}

				return nil, nil
			}()
			assert.NoError(t, err)

			ksConfig := &commonv1.KeystoreInstanceConfig{Values: structConfig}

			// Act
			client, err := aws.NewAWSClient(context.Background(), ksConfig, "us-west-2")

			// Assert
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}
