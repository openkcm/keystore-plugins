package aws_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/keystore-plugins/internal/common"
	aws_keystore "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws"
	awsclient "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
	"github.com/openkcm/keystore-plugins/internal/utils/ptr"
)

func generateTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	// Generate a new RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create a template for the certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	// Encode the certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode the private key to PEM format using PKCS1
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return string(certPEM), string(privPEM)
}

func TestSecretAuthMethod_GetCredentials(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]interface{}
		wantErr    bool
		wantConfig *common.AWSConfig
	}{
		{
			name: "Valid credentials without session token",
			config: map[string]interface{}{
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
			},
			wantErr: false,
			wantConfig: &common.AWSConfig{
				AccessKeyID:     "test-access-key-id",
				SecretAccessKey: "test-secret-access-key",
				SessionToken:    nil,
			},
		},
		{
			name: "Valid credentials with session token",
			config: map[string]interface{}{
				"accessKeyId":     "test-access-key-id",
				"secretAccessKey": "test-secret-access-key",
				"sessionToken":    "test-session-token",
			},
			wantErr: false,
			wantConfig: &common.AWSConfig{
				AccessKeyID:     "test-access-key-id",
				SecretAccessKey: "test-secret-access-key",
				SessionToken:    ptr.PointTo("test-session-token"),
			},
		},
		{
			name: "Missing accessKeyId",
			config: map[string]interface{}{
				"secretAccessKey": "test-secret-access-key",
			},
			wantErr: true,
		},
		{
			name: "Missing secretAccessKey",
			config: map[string]interface{}{
				"accessKeyId": "test-access-key-id",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config, err := structpb.NewStruct(tt.config)
			assert.NoError(t, err)

			reader, err := common.NewStructReader(config)
			assert.NoError(t, err)

			authMethod := &aws_keystore.SecretAuthMethod{}

			// Act
			awsConfig, err := authMethod.GetCredentials(context.Background(), reader)

			// Assert
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && awsConfig != nil {
				assert.Equal(t, tt.wantConfig.AccessKeyID, awsConfig.AccessKeyID)
				assert.Equal(t, tt.wantConfig.SecretAccessKey, awsConfig.SecretAccessKey)

				if tt.wantConfig.SessionToken != nil {
					assert.Equal(t, *tt.wantConfig.SessionToken, *awsConfig.SessionToken)
				} else {
					assert.Nil(t, awsConfig.SessionToken)
				}
			}
		})
	}
}

func TestCertificateAuthMethod_GetCredentials(t *testing.T) {
	clientCert, privateKey := generateTestCertificate(t)

	tests := []struct {
		name                           string
		config                         map[string]interface{}
		mockCreateRolesAnywhereSession func(ctx context.Context, params awsclient.RolesAnywhereParams) (*credentials.StaticCredentialsProvider, error)
		wantErr                        bool
		expectedError                  error
	}{
		{
			name: "Valid credentials",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			mockCreateRolesAnywhereSession: func(ctx context.Context, params awsclient.RolesAnywhereParams) (*credentials.StaticCredentialsProvider, error) {
				provider := credentials.NewStaticCredentialsProvider(
					"mock-access-key-id",
					"mock-secret-access-key",
					"mock-session-token",
				)

				return &provider, nil
			},
			wantErr: false,
		},
		{
			name: "Missing roleArn",
			config: map[string]interface{}{
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing trustAnchorArn",
			config: map[string]interface{}{
				"roleArn":    "test-role-arn",
				"profileArn": "test-profile-arn",
				"clientCert": clientCert,
				"privateKey": privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing profileArn",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing clientCert",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"privateKey":     privateKey,
			},
			wantErr: true,
		},
		{
			name: "Missing privateKey",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
			},
			wantErr: true,
		},
		{
			name: "Invalid clientCert",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     "invalid-base64",
				"privateKey":     privateKey,
			},
			wantErr:       true,
			expectedError: aws_keystore.ErrLoadCert,
		},
		{
			name: "Invalid privateKey",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     "invalid-base64",
			},
			wantErr:       true,
			expectedError: aws_keystore.ErrLoadPrivateKey,
		},
		{
			name: "Error creating roles anywhere session",
			config: map[string]interface{}{
				"roleArn":        "test-role-arn",
				"trustAnchorArn": "test-trust-anchor-arn",
				"profileArn":     "test-profile-arn",
				"clientCert":     clientCert,
				"privateKey":     privateKey,
			},
			mockCreateRolesAnywhereSession: func(ctx context.Context, params awsclient.RolesAnywhereParams) (*credentials.StaticCredentialsProvider, error) {
				return nil, errors.New("mock error")
			},
			wantErr:       true,
			expectedError: aws_keystore.ErrCreateRolesAnywhereSession,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := structpb.NewStruct(tt.config)
			assert.NoError(t, err)

			reader, err := common.NewStructReader(config)
			assert.NoError(t, err)

			authMethod := &aws_keystore.CertificateAuthMethod{
				CreateRolesAnywhereSessionFunc: tt.mockCreateRolesAnywhereSession,
			}

			awsConfig, err := authMethod.GetCredentials(context.Background(), reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
				t.Errorf("GetCredentials() error = %v, expectedError %v", err, tt.expectedError)
			}

			if !tt.wantErr && awsConfig != nil {
				assert.Equal(t, "mock-access-key-id", awsConfig.AccessKeyID)
				assert.Equal(t, "mock-secret-access-key", awsConfig.SecretAccessKey)
				assert.Equal(t, "mock-session-token", *awsConfig.SessionToken)
			}
		})
	}
}

func TestAWSAuthFactory(t *testing.T) {
	tests := []struct {
		authType string
		wantErr  bool
	}{
		{base.AuthTypeSecret, false},
		{base.AuthTypeCertificate, false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.authType, func(t *testing.T) {
			_, err := aws_keystore.AWSAuthFactory(tt.authType)
			if (err != nil) != tt.wantErr {
				t.Errorf("AWSAuthFactory() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
