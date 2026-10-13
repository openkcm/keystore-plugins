package keystoreop

import (
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
)

// ConvertOperationsToBaseKeyAlgorithm maps proto KeyAlgorithm to the provider's algorithm type
func ConvertOperationsToBaseKeyAlgorithm(algo operationsv1.KeyAlgorithm) KeyAlgorithm {
	switch algo {
	case operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256:
		return AES256
	case operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072:
		return RSA3072
	case operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096:
		return RSA4096
	default:
		return ""
	}
}

func ConvertBaseToOperationsKeyAlgorithm(algo KeyAlgorithm) operationsv1.KeyAlgorithm {
	switch algo {
	case AES256:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256
	case RSA3072:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072
	case RSA4096:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096
	default:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

// ConvertOperationsToBaseKeyType maps proto KeyType to the provider's key type
func ConvertOperationsToBaseKeyType(keyType operationsv1.KeyType) KeyType {
	switch keyType {
	case operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED:
		return KeyTypeSystemManaged
	case operationsv1.KeyType_KEY_TYPE_BYOK:
		return KeyTypeBYOK
	case operationsv1.KeyType_KEY_TYPE_HYOK:
		return KeyTypeHYOK
	default:
		return ""
	}
}
