package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/openkcm/keystore-plugins/internal/common"
	aws_client "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
	"github.com/openkcm/keystore-plugins/internal/utils/crypto"
)

const RoleAnywhereSessionDuration = 3600 // 1 hour

var (
	ErrInvalidAuth                = errors.New("invalid authentication type")
	ErrDecodeCert                 = errors.New("failed to decode certificate")
	ErrDecodePrivateKey           = errors.New("failed to decode private key")
	ErrLoadCert                   = errors.New("failed to load certificate")
	ErrLoadPrivateKey             = errors.New("failed to load private key")
	ErrCreateRolesAnywhereSession = errors.New("failed to create AWS Roles Anywhere session")
)

// AWSAuthMethod represents different AWS authentication methods
type AWSAuthMethod interface {
	GetCredentials(ctx context.Context, reader *common.StructReader) (*common.AWSConfig, error)
}

// SecretAuthMethod implements authentication using AWS access key and secret
type SecretAuthMethod struct{}

func (m *SecretAuthMethod) GetCredentials(
	_ context.Context,
	reader *common.StructReader,
) (*common.AWSConfig, error) {
	accessKeyID, err := reader.GetString("accessKeyId")
	if err != nil {
		return nil, err
	}

	secretAccessKey, err := reader.GetString("secretAccessKey")
	if err != nil {
		return nil, err
	}

	// Get optional session token
	var sessionToken *string

	token, err := reader.GetString("sessionToken")
	if err == nil && token != "" {
		sessionToken = &token
	}

	return &common.AWSConfig{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}, nil
}

// CertificateAuthMethod implements authentication using certificate-based auth
type CertificateAuthMethod struct {
	CreateRolesAnywhereSessionFunc func(ctx context.Context, params aws_client.RolesAnywhereParams) (
		*credentials.StaticCredentialsProvider, error)
}

func (m *CertificateAuthMethod) GetCredentials(
	ctx context.Context,
	reader *common.StructReader,
) (*common.AWSConfig, error) {
	// Get required certificate auth parameters
	roleArn, err := reader.GetString("roleArn")
	if err != nil {
		return nil, err
	}

	trustAnchorArn, err := reader.GetString("trustAnchorArn")
	if err != nil {
		return nil, err
	}

	profileArn, err := reader.GetString("profileArn")
	if err != nil {
		return nil, err
	}

	// Get certificate and private key
	clientCertPEM, err := reader.GetString("clientCert")
	if err != nil {
		return nil, err
	}

	privateKeyPEM, err := reader.GetString("privateKey")
	if err != nil {
		return nil, err
	}

	// Load certificate and private key
	clientCert, intermediateCAs, err := crypto.LoadCertificates([]byte(clientCertPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadCert, err)
	}

	privateKey, err := crypto.LoadRSAPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadPrivateKey, err)
	}

	// Create roles anywhere params
	params := aws_client.RolesAnywhereParams{
		ProfileArn:      profileArn,
		RoleArn:         roleArn,
		TrustAnchorArn:  trustAnchorArn,
		RequestTime:     time.Now().UTC(),
		PrivateKey:      privateKey,
		ClientCert:      clientCert,
		IntermediateCAs: intermediateCAs,
		SessionDuration: RoleAnywhereSessionDuration,
	}

	// Get creds from AWS
	creds, err := m.CreateRolesAnywhereSessionFunc(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreateRolesAnywhereSession, err)
	}

	return &common.AWSConfig{
		AccessKeyID:     creds.Value.AccessKeyID,
		SecretAccessKey: creds.Value.SecretAccessKey,
		SessionToken:    &creds.Value.SessionToken,
	}, nil
}

// AWSAuthFactory creates appropriate auth method based on auth type
func AWSAuthFactory(authType string) (AWSAuthMethod, error) {
	switch authType {
	case base.AuthTypeSecret:
		return &SecretAuthMethod{}, nil
	case base.AuthTypeCertificate:
		return &CertificateAuthMethod{
			aws_client.CreateRolesAnywhereSession,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAuth, authType)
	}
}
