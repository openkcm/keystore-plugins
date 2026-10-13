package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/openkcm/internal/aws/rolesanywhere"
	"github.com/openkcm/internal/common"
	"github.com/openkcm/utils/crypto"
)

const RoleAnywhereSessionDuration = 3600 // 1 hour

// AWSConfig holds resolved AWS credentials.
type AWSConfig struct {
	AccessKeyID     string  `json:"accessKeyId"`
	SecretAccessKey string  `json:"secretAccessKey"`
	SessionToken    *string `json:"sessionToken,omitempty"`
}

var (
	ErrInvalidAuth                = errors.New("invalid authentication type")
	ErrLoadCert                   = errors.New("failed to load certificate")
	ErrLoadPrivateKey             = errors.New("failed to load private key")
	ErrCreateRolesAnywhereSession = errors.New("failed to create AWS Roles Anywhere session")
)

// AWSAuthMethod represents different AWS authentication methods
type AWSAuthMethod interface {
	GetCredentials(ctx context.Context, reader *common.StructReader) (*AWSConfig, error)
}

// SecretAuthMethod implements authentication using AWS access key and secret
type SecretAuthMethod struct{}

func (m *SecretAuthMethod) GetCredentials(
	_ context.Context,
	reader *common.StructReader,
) (*AWSConfig, error) {
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

	return &AWSConfig{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}, nil
}

// CertificateAuthMethod implements authentication using certificate-based auth
type CertificateAuthMethod struct {
	CreateRolesAnywhereSessionFunc func(ctx context.Context, params rolesanywhere.Params) (
		*credentials.StaticCredentialsProvider, error)
}

func (m *CertificateAuthMethod) GetCredentials(
	ctx context.Context,
	reader *common.StructReader,
) (*AWSConfig, error) {
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
	params := rolesanywhere.Params{
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

	return &AWSConfig{
		AccessKeyID:     creds.Value.AccessKeyID,
		SecretAccessKey: creds.Value.SecretAccessKey,
		SessionToken:    &creds.Value.SessionToken,
	}, nil
}
