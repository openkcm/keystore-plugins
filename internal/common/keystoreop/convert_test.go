package keystoreop_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/internal/common/keystoreop"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
)

func TestConvertOperationsToBaseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    operationsv1.KeyAlgorithm
		expected keystoreop.KeyAlgorithm
	}{
		{
			name:     "AES256",
			input:    operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			expected: keystoreop.AES256,
		},
		{
			name:     "RSA3072",
			input:    operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
			expected: keystoreop.RSA3072,
		},
		{
			name:     "RSA4096",
			input:    operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096,
			expected: keystoreop.RSA4096,
		},
		{
			name:     "Unknown",
			input:    operationsv1.KeyAlgorithm(999),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := keystoreop.ConvertOperationsToBaseKeyAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertBaseToOperationsKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    keystoreop.KeyAlgorithm
		expected operationsv1.KeyAlgorithm
	}{
		{
			name:     "AES256",
			input:    keystoreop.AES256,
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
		},
		{
			name:     "RSA3072",
			input:    keystoreop.RSA3072,
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
		},
		{
			name:     "RSA4096",
			input:    keystoreop.RSA4096,
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096,
		},
		{
			name:     "Unknown",
			input:    keystoreop.KeyAlgorithm("unknown"),
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := keystoreop.ConvertBaseToOperationsKeyAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertOperationsToBaseKeyType(t *testing.T) {
	tests := []struct {
		name     string
		input    operationsv1.KeyType
		expected keystoreop.KeyType
	}{
		{
			name:     "SystemManaged",
			input:    operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED,
			expected: keystoreop.KeyTypeSystemManaged,
		},
		{
			name:     "BYOK",
			input:    operationsv1.KeyType_KEY_TYPE_BYOK,
			expected: keystoreop.KeyTypeBYOK,
		},
		{
			name:     "Unknown",
			input:    operationsv1.KeyType(999),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := keystoreop.ConvertOperationsToBaseKeyType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
