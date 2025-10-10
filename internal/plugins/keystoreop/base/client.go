package base

import (
	"context"
)

// KeyAlgorithm represents the algorithm of the key.
type KeyAlgorithm string

const (
	AES256  KeyAlgorithm = "AES256"
	RSA3072 KeyAlgorithm = "RSA3072"
	RSA4096 KeyAlgorithm = "RSA4096"
)

type KeyType string

const (
	KeyTypeSystemManaged KeyType = "SYSTEM_MANAGED"
	KeyTypeBYOK          KeyType = "BYOK"
	KeyTypeHYOK          KeyType = "HYOK"
)

const (
	AuthTypeSecret      = "AUTH_TYPE_SECRET"
	AuthTypeCertificate = "AUTH_TYPE_CERTIFICATE"
)

type HashFunction string

const (
	HashFunctionSHA256 HashFunction = "SHA256"
)

type WrappingAlgorithm string

const (
	WrappingAlgorithmCKMRSAPKCSOAEP   WrappingAlgorithm = "CKM_RSA_PKCS_OAEP"
	WrappingAlgorithmCKMRSAAESKEYWRAP WrappingAlgorithm = "CKM_RSA_AES_KEY_WRAP"
)

const (
	// KeyUsageEncryptDecrypt defines default key usage
	// Right now we only support encryption keys for all plugins
	KeyUsageEncryptDecrypt = "ENCRYPT_DECRYPT"
)

// KeyState represents the state of the key.
type KeyState string

const (
	KeyStateEnabled         KeyState = "ENABLED"
	KeyStateDisabled        KeyState = "DISABLED"
	KeyStatePendingDeletion KeyState = "PENDING_DELETION"
	KeyStatePendingImport   KeyState = "PENDING_IMPORT"
	KeyStateUnknown         KeyState = "UNKNOWN"
)

// InvalidStateError it is error that points out that action in Client cannot be executed due to the state of the key.
// For example, trying to delete a key that is already deleted.
type InvalidStateError struct {
	Message string
}

func (e *InvalidStateError) Error() string {
	return e.Message
}

// Client is the interface for native KMS.
// Any KMS providers client we intend to use must implement this interface.
// This requires wrapping an SDK client to conform to this interface.
// For instance, refer to aws.client.
type Client interface {
	GetKey(ctx context.Context, keyID string) (*KeyOutput, error)
	ValidateAccessData(ctx context.Context, keyID string, accessData map[string]string) error
}

// DeleteOptions holds the aws_options for delete actions.
type DeleteOptions struct {
	Window *int32 // The grace period after deletion where the key material still exists in the provider
}

// KeyInput holds the aws_options for creating a key.
type KeyInput struct {
	KeyAlgorithm KeyAlgorithm
	ID           *string
	KeyType      KeyType
}

// KeyOutput holds the information about the key.
type KeyOutput struct {
	ID           string
	KeyAlgorithm KeyAlgorithm
	Usage        string
	Status       string
}

type GetImportParametersOutput struct {
	ID                string
	ProviderParams    string
	PublicKey         string
	ValidTo           string // RFC3339 format
	WrappingAlgorithm string
	HashFunction      string
}
