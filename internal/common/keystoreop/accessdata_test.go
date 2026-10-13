package keystoreop_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/internal/common/keystoreop"
	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
)

type MockProcessor struct{}

func (p MockProcessor) Name() string {
	return "Mock"
}

func (p MockProcessor) ValidateJSONData(jsonData []byte) error {
	var data map[string]interface{}
	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		return commonErrs.NewGrpcErrorWithDetails(
			commonErrs.StatusInvalidKeyAccessData, "CANNOT_PARSE_MOCK_ACCESS_DATA", nil)
	}

	// Validate required fields
	if _, ok := data["requiredField"]; !ok {
		return commonErrs.NewGrpcErrorWithDetails(
			commonErrs.StatusInvalidKeyAccessData, "MISSING_REQUIRED_FIELD", nil)
	}

	return nil
}

func (p MockProcessor) PopulateStructData(
	nativeKeyID string,
	cryptoAccessData map[string]string,
) proto.Message {
	fields := map[string]*structpb.Value{
		"nativeKeyID": structpb.NewStringValue(nativeKeyID),
	}

	for key, value := range cryptoAccessData {
		fields[key] = structpb.NewStringValue(value)
	}

	return &structpb.Struct{
		Fields: fields,
	}
}

func TestValidateKeyAccessDataWithValidInput(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	managementAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"requiredField": structpb.NewStringValue("value1"),
		},
	}
	cryptoAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"instance1": structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"requiredField": structpb.NewStringValue("value1"),
				},
			}),
		},
	}

	err := processor.ValidateKeyAccessData(managementAccessData, cryptoAccessData)

	assert.NoError(t, err)
}

func TestValidateKeyAccessDataWithMissingRequiredFieldInManagementData(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	managementAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{},
	}
	cryptoAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"instance1": structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"requiredField": structpb.NewStringValue("value1"),
				},
			}),
		},
	}

	err := processor.ValidateKeyAccessData(managementAccessData, cryptoAccessData)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, metadata := commonErrs.GetDetails(err)
	assert.Equal(t, "MISSING_REQUIRED_FIELD", reason)
	assert.Equal(t, "management", metadata["type"])

}

func TestValidateKeyAccessDataWithMissingInstanceData(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	managementAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"requiredField": structpb.NewStringValue("value1"),
		},
	}
	cryptoAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"instance1": nil,
		},
	}

	err := processor.ValidateKeyAccessData(managementAccessData, cryptoAccessData)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, metadata := commonErrs.GetDetails(err)
	assert.Equal(t, "MISSING_ACCESS_DATA", reason)
	assert.Equal(t, "crypto", metadata["type"])
	assert.Equal(t, "instance1", metadata["instance"])
}

func TestValidateKeyAccessDataWithInvalidInstanceDataType(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	managementAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"requiredField": structpb.NewStringValue("value1"),
		},
	}
	cryptoAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"instance1": structpb.NewStringValue("invalid"),
		},
	}

	err := processor.ValidateKeyAccessData(managementAccessData, cryptoAccessData)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, metadata := commonErrs.GetDetails(err)
	assert.Equal(t, "INVALID_ACCESS_DATA_TYPE", reason)
	assert.Equal(t, "crypto", metadata["type"])
	assert.Equal(t, "instance1", metadata["instance"])
}

func TestValidateKeyAccessDataWithInvalidInstanceStruct(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	managementAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"requiredField": structpb.NewStringValue("value1"),
		},
	}
	cryptoAccessData := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"instance1": structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"invalidField": structpb.NewStringValue("value"),
				},
			}),
		},
	}

	err := processor.ValidateKeyAccessData(managementAccessData, cryptoAccessData)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, metadata := commonErrs.GetDetails(err)
	assert.Equal(t, "MISSING_REQUIRED_FIELD", reason)
	assert.Equal(t, "crypto", metadata["type"])
	assert.Equal(t, "instance1", metadata["instance"])
}

func TestTransformCryptoAccessDataWithValidInput(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	nativeKeyID := "generic-key-id"
	input := func() []byte {
		data := map[string]json.RawMessage{
			"instance1": json.RawMessage(`{
				"requiredField": "value1",
				"optionalField": "value2"
			}`),
		}
		bytes, _ := json.Marshal(data)
		return bytes
	}()

	result, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result["instance1"])
}

func TestTransformCryptoAccessDataWithMissingRequiredField(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	nativeKeyID := "generic-key-id"
	input := func() []byte {
		data := map[string]json.RawMessage{
			"instance1": json.RawMessage(`{
				"optionalField": "value2"
			}`),
		}
		bytes, _ := json.Marshal(data)
		return bytes
	}()

	_, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, metadata := commonErrs.GetDetails(err)
	assert.Equal(t, "MISSING_REQUIRED_FIELD", reason)
	assert.Equal(t, "instance1", metadata["instance"])
}

func TestTransformCryptoAccessDataWithEmptyInstanceName(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	nativeKeyID := "generic-key-id"
	input := func() []byte {
		data := map[string]json.RawMessage{
			"": json.RawMessage(`{
				"requiredField": "value1",
				"optionalField": "value2"
			}`),
		}
		bytes, _ := json.Marshal(data)
		return bytes
	}()

	_, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, "EMPTY_INSTANCE_NAME", reason)
}

func TestTransformCryptoAccessDataWithInvalidJSON(t *testing.T) {
	processor := keystoreop.NewAccessDataProcessor(MockProcessor{})
	nativeKeyID := "generic-key-id"
	input := []byte(`{
		"instance1": {
			"requiredField": "value1",
			"optionalField": "value2"
	}`) // Malformed JSON

	_, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.Error(t, err)
	assert.True(t, commonErrs.IsStatus(err, commonErrs.StatusInvalidKeyAccessData))

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, "INVALID_PROTO_STRUCT", reason)
}
