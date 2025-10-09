package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
	"github.com/openkcm/keystore-plugins/internal/utils/must"
)

// kmsClient defines the methods of the AWS KMS client that we use.
// This is used for mocking the client in tests.
type kmsClient interface {
	DescribeKey(ctx context.Context,
		params *kms.DescribeKeyInput,
		optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// check if the Client implements the kmsClient interface
var _ kmsClient = (*kms.Client)(nil)

// Client  represents the AWS KMS client
type Client struct {
	internalClient kmsClient
}

// Errors defines the errors that can be returned by the client
var (
	ErrMissingID                          = errors.New("key ID is required")
	ErrNativeCreateKeyFailed              = errors.New("aws key creation failed")
	ErrNativeCreateKeyFailedWrongKeyInput = errors.New("aws key creation failed - wrong key input")
	ErrNativeCreateAliasFailed            = errors.New("aws alias creation failed")
	ErrNativeUpdateAliasFailed            = errors.New("aws alias update failed")
	ErrDescribeKeyFailed                  = errors.New("aws key describe failed")
	ErrGetImportParametersFailed          = errors.New("aws get import parameters failed")
	ErrImportKeyMaterialFailed            = errors.New("aws import key material failed")
	ErrUnknownOptionType                  = errors.New("unknown option type")
	ErrUnsupportedKeySpec                 = errors.New("unsupported key spec")
	ErrUnsupportedKeyUsage                = errors.New("unsupported key usage")
	ErrUnsupportedWrappingAlgorithm       = errors.New("unsupported wrapping algorithm")
)

// newAwsConfig creates a new AWS config with the provided loadConfigOptions
func newAwsConfig(
	ctx context.Context,
	loadConfigOptions ...func(*config.LoadOptions) error,
) aws.Config {
	return must.NotReturnError(config.LoadDefaultConfig(ctx, loadConfigOptions...))
}

// NewClientWithOptions creates a new AWS KMS client with the provided region and credentials provider.
func NewClientWithOptions(
	ctx context.Context,
	region string,
	credentialsProvider aws.CredentialsProvider,
	options ...func(*kms.Options),
) *Client {
	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithCredentialsProvider(credentialsProvider),
	}

	fromConfig := kms.NewFromConfig(newAwsConfig(ctx, loadOptions...), options...)

	return &Client{internalClient: fromConfig}
}

// NewClient creates a new AWS KMS client with the provided region, accessKeyID, and secretAccessKey.
// It also accepts an optional sessionToken.
func NewClient(
	ctx context.Context,
	region, accessKeyID, secretAccessKey string,
	sessionToken ...string,
) *Client {
	var token string
	if len(sessionToken) > 0 {
		token = sessionToken[0]
	}

	return NewClientFromCredentialsProvider(
		ctx,
		region,
		credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, token),
	)
}

// NewClientFromCredentialsProvider creates a new AWS KMS client with the provided credentials provider.
func NewClientFromCredentialsProvider(
	ctx context.Context,
	region string,
	credentialsProvider aws.CredentialsProvider,
) *Client {
	return NewClientWithOptions(ctx, region, credentialsProvider)
}

// NewBaseEndpointClient creates a new AWS KMS client with the provided baseEndpoint.
func NewBaseEndpointClient(
	ctx context.Context,
	region, baseEndpoint string,
) *Client {
	return NewClientWithOptions(
		ctx,
		region,
		credentials.NewStaticCredentialsProvider("dummy", "dummy", ""),
		BaseEndpoint(baseEndpoint),
	)
}

// createKeyInputFromKey converts providers.KeyInput to kms.CreateKeyInput
func createKeyInputFromKeyOptions(
	key base.KeyInput,
) (*kms.CreateKeyInput, error) {
	var keySpec types.KeySpec

	switch key.KeyAlgorithm {
	case base.AES256:
		keySpec = types.KeySpecSymmetricDefault
	case base.RSA3072:
		keySpec = types.KeySpecRsa3072
	case base.RSA4096:
		keySpec = types.KeySpecRsa4096
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownOptionType, key.KeyAlgorithm)
	}

	var origin types.OriginType

	switch key.KeyType {
	case base.KeyTypeSystemManaged:
		origin = types.OriginTypeAwsKms
	case base.KeyTypeBYOK:
		origin = types.OriginTypeExternal
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownOptionType, key.KeyType)
	}

	createKeyInput := &kms.CreateKeyInput{
		KeySpec:  keySpec,
		KeyUsage: types.KeyUsageTypeEncryptDecrypt,
		Origin:   origin,
	}

	return createKeyInput, nil
}

// prepareAlias - returns the alias name for the key with the given id in the format "alias/{id}-primary"
func prepareAlias(id string) string {
	return fmt.Sprintf("alias/%s-primary", id)
}

// convertKeySpecToKeyAlgorithm converts kms.KeySpec to base.KeyAlgorithm
func convertKeySpecToKeyAlgorithm(keySpec types.KeySpec) (base.KeyAlgorithm, error) {
	switch keySpec {
	case types.KeySpecSymmetricDefault:
		return base.AES256, nil
	case types.KeySpecRsa3072:
		return base.RSA3072, nil
	case types.KeySpecRsa4096:
		return base.RSA4096, nil
	default:
		return "", fmt.Errorf("%w: %v", ErrUnsupportedKeySpec, keySpec)
	}
}

func convertKeyStateToBaseKeyState(keyState types.KeyState) base.KeyState {
	switch keyState {
	case types.KeyStateEnabled:
		return base.KeyStateEnabled
	case types.KeyStateDisabled:
		return base.KeyStateDisabled
	case types.KeyStatePendingDeletion:
		return base.KeyStatePendingDeletion
	case types.KeyStatePendingImport:
		return base.KeyStatePendingImport
	default:
		return base.KeyStateUnknown
	}
}

func convertToBaseWrapAlgAndHash(
	wrappingAlgorithm types.AlgorithmSpec,
) (base.WrappingAlgorithm, base.HashFunction, error) {
	switch wrappingAlgorithm {
	case types.AlgorithmSpecRsaesOaepSha256:
		return base.WrappingAlgorithmCKMRSAPKCSOAEP, base.HashFunctionSHA256, nil
	case types.AlgorithmSpecRsaAesKeyWrapSha256:
		return base.WrappingAlgorithmCKMRSAAESKEYWRAP, base.HashFunctionSHA256, nil
	default:
		return "", "", fmt.Errorf("%w: %v", ErrUnsupportedWrappingAlgorithm, wrappingAlgorithm)
	}
}

func (c *Client) GetKey(
	ctx context.Context,
	keyID string,
) (*base.KeyOutput, error) {
	if keyID == "" {
		return nil, ErrMissingID
	}

	describeKeyInput := &kms.DescribeKeyInput{
		KeyId: &keyID,
	}

	result, err := c.internalClient.DescribeKey(ctx, describeKeyInput)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDescribeKeyFailed, err)
	}

	if result.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyUsage, result.KeyMetadata.KeyUsage)
	}

	keyAlgorithm, err := convertKeySpecToKeyAlgorithm(result.KeyMetadata.KeySpec)
	if err != nil {
		return nil, err
	}

	keyState := convertKeyStateToBaseKeyState(result.KeyMetadata.KeyState)

	return &base.KeyOutput{
		ID:           keyID,
		KeyAlgorithm: keyAlgorithm,
		Usage:        base.KeyUsageEncryptDecrypt,
		Status:       string(keyState),
	}, nil
}

// NewClientForTests - new client for unit tests
func NewClientForTests(internal kmsClient) *Client {
	return &Client{internalClient: internal}
}

// ExportInternalClient - exported internalClient
func (c *Client) ExportInternalClient() *kms.Client {
	internalClient, ok := c.internalClient.(*kms.Client)
	if !ok {
		panic(fmt.Sprintf("expected *kms.Client, got %T", c.internalClient))
	}

	return internalClient
}
