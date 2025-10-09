package base_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
)

type MockProcessor struct{}

func (p MockProcessor) Name() string {
	return "Mock"
}

func (p MockProcessor) ValidateJSONData(jsonData []byte) error {
	var data map[string]interface{}

	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		return fmt.Errorf("failed to parse JSON data: %v", err)
	}

	// Validate required fields
	if _, ok := data["requiredField"]; !ok {
		return errors.New("missing requiredField")
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
	processor := base.NewAccessDataProcessor(MockProcessor{})
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
	processor := base.NewAccessDataProcessor(MockProcessor{})
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
	assert.Contains(t, err.Error(), "invalid Mock key management access data")
}

func TestValidateKeyAccessDataWithMissingInstanceData(t *testing.T) {
	processor := base.NewAccessDataProcessor(MockProcessor{})
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
	assert.Contains(t, err.Error(), "missing Mock crypto access data for instance: instance1")
}

func TestValidateKeyAccessDataWithInvalidInstanceDataType(t *testing.T) {
	processor := base.NewAccessDataProcessor(MockProcessor{})
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
	assert.Contains(t, err.Error(), "invalid data type for Mock crypto access data for instance: instance1")
}

func TestValidateKeyAccessDataWithInvalidInstanceStruct(t *testing.T) {
	processor := base.NewAccessDataProcessor(MockProcessor{})
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
	assert.Contains(t, err.Error(), "invalid Mock key access data for instance instance1")
}

func TestTransformCryptoAccessDataWithValidInput(t *testing.T) {
	processor := base.NewAccessDataProcessor(MockProcessor{})
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
	processor := base.NewAccessDataProcessor(MockProcessor{})
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

	result, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing requiredField")
	assert.Nil(t, result)
}

func TestTransformCryptoAccessDataWithEmptyInstanceName(t *testing.T) {
	processor := base.NewAccessDataProcessor(MockProcessor{})
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

	result, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "instance name cannot be empty")
	assert.Nil(t, result)
}

func TestTransformCryptoAccessDataWithInvalidJSON(t *testing.T) {
	processor := base.NewAccessDataProcessor(MockProcessor{})
	nativeKeyID := "generic-key-id"
	input := []byte(`{
		"instance1": {
			"requiredField": "value1",
			"optionalField": "value2"
	}`) // Malformed JSON

	result, err := processor.TransformCryptoAccessData(nativeKeyID, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal crypto access data")
	assert.Nil(t, result)
}
