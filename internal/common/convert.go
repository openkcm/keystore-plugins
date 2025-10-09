package common

import (
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"

	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
)

// ConvertOperationsToBaseKeyAlgorithm maps proto KeyAlgorithm to the provider's algorithm type
func ConvertOperationsToBaseKeyAlgorithm(algo operationsv1.KeyAlgorithm) base.KeyAlgorithm {
	switch algo {
	case operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256:
		return base.AES256
	case operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072:
		return base.RSA3072
	case operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096:
		return base.RSA4096
	default:
		return ""
	}
}

func ConvertBaseToOperationsKeyAlgorithm(algo base.KeyAlgorithm) operationsv1.KeyAlgorithm {
	switch algo {
	case base.AES256:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256
	case base.RSA3072:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072
	case base.RSA4096:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096
	default:
		return operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

// ConvertOperationsToBaseKeyType maps proto KeyType to the provider's key type
func ConvertOperationsToBaseKeyType(keyType operationsv1.KeyType) base.KeyType {
	switch keyType {
	case operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED:
		return base.KeyTypeSystemManaged
	case operationsv1.KeyType_KEY_TYPE_BYOK:
		return base.KeyTypeBYOK
	case operationsv1.KeyType_KEY_TYPE_HYOK:
		return base.KeyTypeHYOK
	default:
		return ""
	}
}
