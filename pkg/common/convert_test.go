package common_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"

	"github.com/openkcm/keystore-plugins/pkg/common"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/base"
)

func TestConvertOperationsToBaseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    operationsv1.KeyAlgorithm
		expected base.KeyAlgorithm
	}{
		{
			name:     "AES256",
			input:    operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
			expected: base.AES256,
		},
		{
			name:     "RSA3072",
			input:    operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
			expected: base.RSA3072,
		},
		{
			name:     "RSA4096",
			input:    operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096,
			expected: base.RSA4096,
		},
		{
			name:     "Unknown",
			input:    operationsv1.KeyAlgorithm(999),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := common.ConvertOperationsToBaseKeyAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertBaseToOperationsKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    base.KeyAlgorithm
		expected operationsv1.KeyAlgorithm
	}{
		{
			name:     "AES256",
			input:    base.AES256,
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_AES256,
		},
		{
			name:     "RSA3072",
			input:    base.RSA3072,
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA3072,
		},
		{
			name:     "RSA4096",
			input:    base.RSA4096,
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_RSA4096,
		},
		{
			name:     "Unknown",
			input:    base.KeyAlgorithm("unknown"),
			expected: operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := common.ConvertBaseToOperationsKeyAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertOperationsToBaseKeyType(t *testing.T) {
	tests := []struct {
		name     string
		input    operationsv1.KeyType
		expected base.KeyType
	}{
		{
			name:     "SystemManaged",
			input:    operationsv1.KeyType_KEY_TYPE_SYSTEM_MANAGED,
			expected: base.KeyTypeSystemManaged,
		},
		{
			name:     "BYOK",
			input:    operationsv1.KeyType_KEY_TYPE_BYOK,
			expected: base.KeyTypeBYOK,
		},
		{
			name:     "Unknown",
			input:    operationsv1.KeyType(999),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := common.ConvertOperationsToBaseKeyType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
