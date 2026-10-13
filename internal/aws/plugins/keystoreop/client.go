package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"github.com/openkcm/internal/common/keystoreop"
	cryptoUtils "github.com/openkcm/utils/crypto"
	"github.com/openkcm/utils/must"
	"github.com/openkcm/utils/ptr"
)

// kmsClient defines the methods of the AWS KMS client that we use.
// This is used for mocking the client in tests.
type kmsClient interface {
	CreateKey(ctx context.Context,
		params *kms.CreateKeyInput,
		optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	EnableKey(ctx context.Context,
		params *kms.EnableKeyInput,
		optFns ...func(*kms.Options)) (*kms.EnableKeyOutput, error)
	DisableKey(ctx context.Context,
		params *kms.DisableKeyInput,
		optFns ...func(*kms.Options)) (*kms.DisableKeyOutput, error)
	ScheduleKeyDeletion(ctx context.Context,
		params *kms.ScheduleKeyDeletionInput,
		optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	CreateAlias(ctx context.Context,
		params *kms.CreateAliasInput,
		optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	UpdateAlias(ctx context.Context,
		params *kms.UpdateAliasInput,
		optFns ...func(*kms.Options)) (*kms.UpdateAliasOutput, error)
	DescribeKey(ctx context.Context,
		params *kms.DescribeKeyInput,
		optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetParametersForImport(ctx context.Context,
		params *kms.GetParametersForImportInput,
		optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context,
		params *kms.ImportKeyMaterialInput,
		optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
	ListKeyRotations(ctx context.Context,
		params *kms.ListKeyRotationsInput,
		optFns ...func(*kms.Options)) (*kms.ListKeyRotationsOutput, error)
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
	ErrNativeCreateKeyFailedWrongKeyInput = errors.New(
		"aws key creation failed - wrong key input",
	)
	ErrNativeCreateAliasFailed      = errors.New("aws alias creation failed")
	ErrNativeUpdateAliasFailed      = errors.New("aws alias update failed")
	ErrNativeDeleteKeyVersionFailed = errors.New("aws key deletion failed")
	ErrNativeKeyNotFound            = errors.New("aws key not found")
	ErrEnabledKeyFailed             = errors.New("aws key enable failed")
	ErrDisabledKeyFailed            = errors.New("aws key disable failed")
	ErrAccessDenied                 = errors.New("aws access denied")
	ErrListKeyRotationsFailed       = errors.New("aws list key rotations failed")
	ErrDescribeKeyFailed            = errors.New("aws key describe failed")
	ErrGetImportParametersFailed    = errors.New("aws get import parameters failed")
	ErrImportKeyMaterialFailed      = errors.New("aws import key material failed")
	ErrInvalidKeyMaterial           = errors.New("aws invalid key material: ciphertext could not be decrypted")
	ErrUnknownOptionType            = errors.New("unknown option type")
	ErrUnsupportedKeySpec           = errors.New("unsupported key spec")
	ErrUnsupportedKeyUsage          = errors.New("unsupported key usage")
	ErrUnsupportedWrappingAlgorithm = errors.New("unsupported wrapping algorithm")
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
	key keystoreop.KeyInput,
) (*kms.CreateKeyInput, error) {
	var keySpec types.KeySpec

	switch key.KeyAlgorithm {
	case keystoreop.AES256:
		keySpec = types.KeySpecSymmetricDefault
	case keystoreop.RSA3072:
		keySpec = types.KeySpecRsa3072
	case keystoreop.RSA4096:
		keySpec = types.KeySpecRsa4096
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownOptionType, key.KeyAlgorithm)
	}

	var origin types.OriginType
	switch key.KeyType {
	case keystoreop.KeyTypeSystemManaged:
		origin = types.OriginTypeAwsKms
	case keystoreop.KeyTypeBYOK:
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

// CreateKey creates a new key with the given keyInput
func (c *Client) CreateKey(
	ctx context.Context,
	keyInput keystoreop.KeyInput,
) (*keystoreop.KeyOutput, error) {
	if keyInput.ID == nil {
		return nil, ErrMissingID
	}

	createKeyInput, err := createKeyInputFromKeyOptions(keyInput)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNativeCreateKeyFailedWrongKeyInput, err)
	}

	result, err := c.internalClient.CreateKey(ctx, createKeyInput)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNativeCreateKeyFailed, err)
	}

	arn := result.KeyMetadata.Arn

	err = c.ensureAlias(ctx, *arn, *keyInput.ID)
	if err != nil {
		return nil, err
	}

	keyState := convertKeyStateToBaseKeyState(result.KeyMetadata.KeyState)

	return &keystoreop.KeyOutput{
		ID:     *arn,
		Status: string(keyState),
	}, nil
}

// ensureAlias ensures that the alias for the key with the given keyID exists
func (c *Client) ensureAlias(ctx context.Context, keyID, id string) error {
	alias := prepareAlias(id)

	if err := c.createAlias(ctx, keyID, alias); err != nil {
		var alreadyExistsException *types.AlreadyExistsException
		if !errors.As(err, &alreadyExistsException) {
			return err
		}
		// Alias already existed (e.g. from a prior partial create) — update it to point to the new key.
		return c.updateAlias(ctx, keyID, alias)
	}

	return nil
}

// createAlias creates an alias with the given aliasName for the key with the given keyID
func (c *Client) createAlias(ctx context.Context, keyID, aliasName string) error {
	_, err := c.internalClient.CreateAlias(ctx,
		&kms.CreateAliasInput{
			AliasName:   ptr.PointTo(aliasName),
			TargetKeyId: ptr.PointTo(keyID),
		})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNativeCreateAliasFailed, err)
	}

	return nil
}

// updateAlias updates the alias with the given aliasName to point to the key with the given keyID
func (c *Client) updateAlias(ctx context.Context, keyID, aliasName string) error {
	_, err := c.internalClient.UpdateAlias(ctx, &kms.UpdateAliasInput{
		AliasName:   ptr.PointTo(aliasName),
		TargetKeyId: ptr.PointTo(keyID),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNativeUpdateAliasFailed, err)
	}

	return nil
}

// createScheduleKeyDeletionInputFromDeleteOptions converts providers.DeleteOptions to kms.ScheduleKeyDeletionInput
func createScheduleKeyDeletionInputFromDeleteOptions(
	keyID string,
	options keystoreop.DeleteOptions,
) *kms.ScheduleKeyDeletionInput {
	if options.Window != nil {
		return &kms.ScheduleKeyDeletionInput{
			KeyId:               &keyID,
			PendingWindowInDays: options.Window,
		}
	}

	return &kms.ScheduleKeyDeletionInput{
		KeyId: &keyID,
	}
}

// DeleteKey deletes the key with the given keyID
func (c *Client) DeleteKey(
	ctx context.Context,
	keyID string,
	options keystoreop.DeleteOptions,
) error {
	input := createScheduleKeyDeletionInputFromDeleteOptions(keyID, options)

	_, err := c.internalClient.ScheduleKeyDeletion(ctx, input)
	if err != nil {
		var kmsInvalidStateException *types.KMSInvalidStateException
		if errors.As(err, &kmsInvalidStateException) {
			stateErr := keystoreop.InvalidStateError{Message: "key is probably already deleted"}
			return fmt.Errorf("%w: %w", &stateErr, err)
		}

		return fmt.Errorf("%w: %w", ErrNativeDeleteKeyVersionFailed, err)
	}

	return nil
}

// EnableKey enables the key with the given keyID
func (c *Client) EnableKey(ctx context.Context, keyID string) error {
	_, err := c.internalClient.EnableKey(ctx, &kms.EnableKeyInput{KeyId: ptr.PointTo(keyID)})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEnabledKeyFailed, err)
	}

	return nil
}

// DisableKey disables the key with the given keyID
func (c *Client) DisableKey(ctx context.Context, keyID string) error {
	_, err := c.internalClient.DisableKey(
		ctx,
		&kms.DisableKeyInput{KeyId: ptr.PointTo(keyID)},
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDisabledKeyFailed, err)
	}

	return nil
}

// convertKeySpecToKeyAlgorithm converts kms.KeySpec to keystoreop.KeyAlgorithm
func convertKeySpecToKeyAlgorithm(keySpec types.KeySpec) (keystoreop.KeyAlgorithm, error) {
	switch keySpec {
	case types.KeySpecSymmetricDefault:
		return keystoreop.AES256, nil
	case types.KeySpecRsa3072:
		return keystoreop.RSA3072, nil
	case types.KeySpecRsa4096:
		return keystoreop.RSA4096, nil
	default:
		return "", fmt.Errorf("%w: %v", ErrUnsupportedKeySpec, keySpec)
	}
}

func convertKeyStateToBaseKeyState(keyState types.KeyState) keystoreop.KeyState {
	switch keyState {
	case types.KeyStateEnabled:
		return keystoreop.KeyStateEnabled
	case types.KeyStateDisabled:
		return keystoreop.KeyStateDisabled
	case types.KeyStatePendingDeletion:
		return keystoreop.KeyStatePendingDeletion
	case types.KeyStatePendingImport:
		return keystoreop.KeyStatePendingImport
	default:
		return keystoreop.KeyStateUnknown
	}
}

func convertKeyVersionState(keyState types.KeyMaterialState) string {
	return "N/A"
}

func convertToBaseWrapAlgAndHash(
	wrappingAlgorithm types.AlgorithmSpec,
) (keystoreop.WrappingAlgorithm, keystoreop.HashFunction, error) {
	switch wrappingAlgorithm {
	case types.AlgorithmSpecRsaesOaepSha256:
		return keystoreop.WrappingAlgorithmCKMRSAPKCSOAEP, keystoreop.HashFunctionSHA256, nil
	case types.AlgorithmSpecRsaAesKeyWrapSha256:
		return keystoreop.WrappingAlgorithmCKMRSAAESKEYWRAP, keystoreop.HashFunctionSHA256, nil
	default:
		return "", "", fmt.Errorf("%w: %v", ErrUnsupportedWrappingAlgorithm, wrappingAlgorithm)
	}
}

func (c *Client) GetKeyVerions(ctx context.Context, keyID string) ([]*keystoreop.KeyVersion, error) {
	// AWS doesn't provide a way to order the versions
	rotationResult, err := c.internalClient.ListKeyRotations(ctx, &kms.ListKeyRotationsInput{
		KeyId:              &keyID,
		IncludeKeyMaterial: types.IncludeKeyMaterialAllKeyMaterial,
	})
	if err != nil {
		var operationErr *smithy.OperationError
		if errors.As(err, &operationErr) {
			var apiErr smithy.APIError
			if errors.As(operationErr.Err, &apiErr) {
				if apiErr.ErrorCode() == "AccessDeniedException" {
					return nil, fmt.Errorf("%w: %v", ErrAccessDenied, apiErr.ErrorMessage())
				}
				return nil, fmt.Errorf("%w: %v", ErrListKeyRotationsFailed, apiErr.ErrorMessage())
			}
		}
		return nil, fmt.Errorf("%w: %w", ErrListKeyRotationsFailed, err)
	}

	slices.SortFunc(rotationResult.Rotations, func(a, b types.RotationsListEntry) int {
		if a.RotationDate == nil && b.RotationDate == nil {
			return 0
		}
		if a.RotationDate == nil {
			return 1
		}
		if b.RotationDate == nil {
			return -1
		}
		return b.RotationDate.Compare(*a.RotationDate)
	})

	versions := make([]*keystoreop.KeyVersion, 0, len(rotationResult.Rotations))
	for _, v := range rotationResult.Rotations {
		versions = append(versions, &keystoreop.KeyVersion{
			ID:           *v.KeyMaterialId,
			CreationTime: v.RotationDate,
			Status:       convertKeyVersionState(v.KeyMaterialState),
		})
	}
	return versions, nil
}

func (c *Client) GetKey(
	ctx context.Context,
	keyID string,
) (*keystoreop.KeyOutput, error) {
	if keyID == "" {
		return nil, ErrMissingID
	}

	describeKeyInput := &kms.DescribeKeyInput{
		KeyId: &keyID,
	}

	result, err := c.internalClient.DescribeKey(ctx, describeKeyInput)
	if err != nil {
		var (
			notFoundExc  *types.NotFoundException
			operationErr *smithy.OperationError
		)

		switch {
		case errors.As(err, &notFoundExc):
			return nil, ErrNativeKeyNotFound
		case errors.As(err, &operationErr):
			var apiErr smithy.APIError
			if errors.As(operationErr.Err, &apiErr) {
				if apiErr.ErrorCode() == "AccessDeniedException" {
					return nil, fmt.Errorf("%w: %v", ErrAccessDenied, apiErr.ErrorMessage())
				}
				return nil, fmt.Errorf("%w: %v", ErrDescribeKeyFailed, apiErr.ErrorMessage())
			}
			return nil, fmt.Errorf("%w: %w", ErrDescribeKeyFailed, err)
		default:
			return nil, fmt.Errorf("%w: %w", ErrDescribeKeyFailed, err)
		}
	}

	if result.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyUsage, result.KeyMetadata.KeyUsage)
	}

	keyAlgorithm, err := convertKeySpecToKeyAlgorithm(result.KeyMetadata.KeySpec)
	if err != nil {
		return nil, err
	}

	keyState := convertKeyStateToBaseKeyState(result.KeyMetadata.KeyState)

	var currentVersionID string

	// Get current version ID from DescribeKey metadata
	if result.KeyMetadata.CurrentKeyMaterialId != nil {
		currentVersionID = *result.KeyMetadata.CurrentKeyMaterialId
	}

	return &keystoreop.KeyOutput{
		ID:               keyID,
		KeyAlgorithm:     keyAlgorithm,
		Usage:            keystoreop.KeyUsageEncryptDecrypt,
		Status:           string(keyState),
		CurrentVersionID: currentVersionID,
	}, nil
}

// GetImportParameters retrieves the parameters required for importing key material.
func (c *Client) GetImportParameters(
	ctx context.Context,
	keyID string,
	keyAlgorithm keystoreop.KeyAlgorithm,
) (*keystoreop.GetImportParametersOutput, error) {
	if keyID == "" {
		return nil, ErrMissingID
	}

	var wrappingAlgorithm types.AlgorithmSpec
	switch keyAlgorithm {
	case keystoreop.AES256:
		wrappingAlgorithm = types.AlgorithmSpecRsaesOaepSha256
	case keystoreop.RSA3072, keystoreop.RSA4096:
		wrappingAlgorithm = types.AlgorithmSpecRsaAesKeyWrapSha256
	default:
		return nil, fmt.Errorf("%w: unsupported key algorithm %v", ErrUnsupportedKeySpec, keyAlgorithm)
	}

	input := &kms.GetParametersForImportInput{
		KeyId:             &keyID,
		WrappingAlgorithm: wrappingAlgorithm,
		WrappingKeySpec:   types.WrappingKeySpecRsa4096,
	}

	output, err := c.internalClient.GetParametersForImport(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetImportParametersFailed, err)
	}

	wrappingAlgorithmBase, hashFunction, err := convertToBaseWrapAlgAndHash(
		wrappingAlgorithm,
	)
	if err != nil {
		return nil, err
	}

	return &keystoreop.GetImportParametersOutput{
		ID:                keyID,
		ProviderParams:    base64.StdEncoding.EncodeToString(output.ImportToken),
		PublicKey:         cryptoUtils.EncodeToPem(output.PublicKey, cryptoUtils.PEMArmorPublicKey),
		ValidTo:           output.ParametersValidTo.Format(time.RFC3339),
		WrappingAlgorithm: string(wrappingAlgorithmBase),
		HashFunction:      string(hashFunction),
	}, nil
}

// ImportKeyMaterial imports the encrypted key material into AWS KMS.
func (c *Client) ImportKeyMaterial(
	ctx context.Context,
	keyID string,
	importToken, encryptedKeyMaterial []byte,
) error {
	if keyID == "" {
		return ErrMissingID
	}

	input := &kms.ImportKeyMaterialInput{
		KeyId:                &keyID,
		ImportToken:          importToken,
		EncryptedKeyMaterial: encryptedKeyMaterial,
		ExpirationModel:      types.ExpirationModelTypeKeyMaterialDoesNotExpire,
	}

	_, err := c.internalClient.ImportKeyMaterial(ctx, input)
	if err != nil {
		var invalidCiphertextErr *types.InvalidCiphertextException
		if errors.As(err, &invalidCiphertextErr) {
			return fmt.Errorf("%w: %w", ErrInvalidKeyMaterial, err)
		}
		return fmt.Errorf("%w: %w", ErrImportKeyMaterialFailed, err)
	}

	return nil
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
