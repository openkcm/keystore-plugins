package base

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type ProviderProcessor interface {
	Name() string
	ValidateJSONData(jsonData []byte) error
	PopulateStructData(nativeKeyID string, cryptoAccessData map[string]string) proto.Message
}

type AccessDataProcessor struct {
	providerName      string
	providerProcessor ProviderProcessor
}

func NewAccessDataProcessor(processor ProviderProcessor) *AccessDataProcessor {
	return &AccessDataProcessor{
		providerName:      processor.Name(),
		providerProcessor: processor,
	}
}

func (adp *AccessDataProcessor) ValidateKeyAccessData(
	managementAccessData *structpb.Struct,
	cryptoAccessData *structpb.Struct,
) error {
	err := adp.validateKeyAccessDataStruct(managementAccessData)
	if err != nil {
		return fmt.Errorf("invalid %s key management access data: %v", adp.providerName, err)
	}

	for instanceName, instanceData := range cryptoAccessData.AsMap() {
		if instanceData == nil {
			return fmt.Errorf("missing %s crypto access data for instance: %s", adp.providerName, instanceName)
		}

		data, ok := instanceData.(map[string]any)
		if !ok {
			return fmt.Errorf(
				"invalid data type for %s crypto access data for instance: %s",
				adp.providerName, instanceName)
		}

		structData, err := structpb.NewStruct(data)
		if err != nil {
			return fmt.Errorf(
				"failed to convert %s crypto access data to proto struct for instance %s: %v",
				adp.providerName, instanceName, err)
		}

		err = adp.validateKeyAccessDataStruct(structData)
		if err != nil {
			return fmt.Errorf("invalid %s key access data for instance %s: %v", adp.providerName, instanceName, err)
		}
	}

	return nil
}

func (adp *AccessDataProcessor) TransformCryptoAccessData(
	nativeKeyID string,
	jsonAccessData []byte,
) (map[string][]byte, error) {
	cryptoAccessDataMap := make(map[string]json.RawMessage)
	transformedCryptoAccessDataMap := make(map[string][]byte)

	err := json.Unmarshal(jsonAccessData, &cryptoAccessDataMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal crypto access data: %w", err)
	}

	for instanceName, cryptoAccessDataJson := range cryptoAccessDataMap {
		if instanceName == "" {
			return nil, fmt.Errorf("instance name cannot be empty at position %s in crypto access data", instanceName)
		}

		err = adp.providerProcessor.ValidateJSONData(cryptoAccessDataJson)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid %s key access data for instance %s: %w",
				adp.providerName, instanceName, err)
		}

		cryptoAccessData := make(map[string]string)

		err = json.Unmarshal(cryptoAccessDataJson, &cryptoAccessData)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to transform %s crypto access data for instance %s: %w",
				adp.providerName, instanceName, err)
		}

		cryptoAccessProto := adp.providerProcessor.PopulateStructData(nativeKeyID, cryptoAccessData)

		cryptoAccessProtoBytes, err := proto.Marshal(cryptoAccessProto)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to transform %s crypto access data for instance %s: %w",
				adp.providerName, instanceName, err)
		}

		transformedCryptoAccessDataMap[instanceName] = cryptoAccessProtoBytes
	}

	return transformedCryptoAccessDataMap, nil
}

func (adp *AccessDataProcessor) validateKeyAccessDataStruct(data *structpb.Struct) error {
	jsonData, err := protojson.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to read data: %v", err)
	}

	return adp.providerProcessor.ValidateJSONData(jsonData)
}
