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

// --- Mock Processor ---

type MockProcessor struct{}

func (p MockProcessor) Name() string {
	return "Mock"
}

func (p MockProcessor) ValidateJSONData(jsonData []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to parse JSON data: %v", err)
	}

	if _, ok := data["requiredField"]; !ok {
		return errors.New("missing requiredField")
	}

	return nil
}

func (p MockProcessor) PopulateStructData(nativeKeyID string, cryptoAccessData map[string]string) proto.Message {
	fields := map[string]*structpb.Value{
		"nativeKeyID": structpb.NewStringValue(nativeKeyID),
	}
	for key, value := range cryptoAccessData {
		fields[key] = structpb.NewStringValue(value)
	}

	return &structpb.Struct{Fields: fields}
}

// --- Helpers ---

func newProcessor() *base.AccessDataProcessor {
	return base.NewAccessDataProcessor(MockProcessor{})
}

func newStruct(fields map[string]string) *structpb.Struct {
	s := &structpb.Struct{Fields: map[string]*structpb.Value{}}
	for k, v := range fields {
		s.Fields[k] = structpb.NewStringValue(v)
	}

	return s
}

func validateKeyAccess(t *testing.T, managementFields map[string]string, cryptoFields map[string]map[string]string, expectedErr string) {
	t.Helper()

	processor := newProcessor()

	managementAccessData := newStruct(managementFields)

	cryptoAccessData := &structpb.Struct{Fields: map[string]*structpb.Value{}}

	for instance, fields := range cryptoFields {
		if fields == nil {
			cryptoAccessData.Fields[instance] = nil
		} else {
			cryptoAccessData.Fields[instance] = structpb.NewStructValue(newStruct(fields))
		}
	}

	err := processor.ValidateKeyAccessData(managementAccessData, cryptoAccessData)

	if expectedErr == "" {
		assert.NoError(t, err)
	} else {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedErr)
	}
}

func transformCryptoAccess(t *testing.T, nativeKeyID string, input map[string]string, expectedErr string) {
	t.Helper()

	processor := newProcessor()

	bytes, _ := json.Marshal(func() map[string]json.RawMessage {
		out := map[string]json.RawMessage{}
		for k, v := range input {
			out[k] = json.RawMessage(v)
		}

		return out
	}())

	result, err := processor.TransformCryptoAccessData(nativeKeyID, bytes)

	if expectedErr == "" {
		assert.NoError(t, err)
		assert.NotNil(t, result)
	} else {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedErr)
		assert.Nil(t, result)
	}
}

// --- Tests ---

func TestValidateKeyAccessData(t *testing.T) {
	validateKeyAccess(t,
		map[string]string{"requiredField": "value1"},
		map[string]map[string]string{"instance1": {"requiredField": "value1"}},
		"",
	)

	validateKeyAccess(t,
		map[string]string{},
		map[string]map[string]string{"instance1": {"requiredField": "value1"}},
		"invalid Mock key management access data",
	)

	validateKeyAccess(t,
		map[string]string{"requiredField": "value1"},
		map[string]map[string]string{"instance1": nil},
		"missing Mock crypto access data for instance: instance1",
	)

	validateKeyAccess(t,
		map[string]string{"requiredField": "value1"},
		map[string]map[string]string{"instance1": {"invalidField": "value"}},
		"invalid Mock key access data for instance instance1",
	)
}

func TestTransformCryptoAccessData(t *testing.T) {
	transformCryptoAccess(t, "generic-key-id",
		map[string]string{"instance1": `{"requiredField": "value1", "optionalField": "value2"}`},
		"",
	)

	transformCryptoAccess(t, "generic-key-id",
		map[string]string{"instance1": `{"optionalField": "value2"}`},
		"missing requiredField",
	)

	transformCryptoAccess(t, "generic-key-id",
		map[string]string{"": `{"requiredField": "value1", "optionalField": "value2"}`},
		"instance name cannot be empty",
	)

	// Malformed JSON
	processor := newProcessor()
	invalidJSON := []byte(`{"instance1": {"requiredField": "value1","optionalField": "value2"}`) // missing closing brace
	result, err := processor.TransformCryptoAccessData("generic-key-id", invalidJSON)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal crypto access data")
	assert.Nil(t, result)
}
