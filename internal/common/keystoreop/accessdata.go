package keystoreop

import (
	"encoding/json"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
)

const (
	GrpcErrorReasonMissingAccessData     = "MISSING_ACCESS_DATA"
	GrpcErrorReasonInvalidAccessDataType = "INVALID_ACCESS_DATA_TYPE"
	GrpcErrorReasonInvalidProtoStruct    = "INVALID_PROTO_STRUCT"
	GrpcErrorReasonEmptyInstanceName     = "EMPTY_INSTANCE_NAME"
)

// Metadata keys and values attached to access data validation errors.
const (
	metadataKeyType          = "type"
	metadataKeyInstance      = "instance"
	accessDataTypeManagement = "management"
	accessDataTypeCrypto     = "crypto"
)

type ProviderProcessor interface {
	Name() string

	// ValidateJSONData must return a GRPC error status if validation fails
	ValidateJSONData(jsonData []byte) error

	PopulateStructData(nativeKeyID string, cryptoAccessData map[string]string) proto.Message
}

type AccessDataProcessor struct {
	providerName      string
	providerProcessor ProviderProcessor
	logger            hclog.Logger
}

func NewAccessDataProcessor(processor ProviderProcessor) *AccessDataProcessor {
	return &AccessDataProcessor{
		providerName:      processor.Name(),
		providerProcessor: processor,
	}
}

func (adp *AccessDataProcessor) SetLogger(logger hclog.Logger) {
	adp.logger = logger
}

func (adp *AccessDataProcessor) ValidateKeyAccessData(
	managementAccessData *structpb.Struct,
	cryptoAccessData *structpb.Struct,
) error {
	err := adp.validateKeyAccessDataStruct(managementAccessData)
	if err != nil {
		return commonErrs.WithMetadata(err, map[string]string{
			metadataKeyType: accessDataTypeManagement,
		})
	}

	for instanceName, instanceData := range cryptoAccessData.AsMap() {
		if instanceData == nil {
			return commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonMissingAccessData,
				map[string]string{
					metadataKeyType:     accessDataTypeCrypto,
					metadataKeyInstance: instanceName,
				})
		}

		data, ok := instanceData.(map[string]any)
		if !ok {
			return commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidAccessDataType,
				map[string]string{
					metadataKeyType:     accessDataTypeCrypto,
					metadataKeyInstance: instanceName,
				})
		}

		structData, err := structpb.NewStruct(data)
		if err != nil {
			return commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidProtoStruct,
				map[string]string{
					metadataKeyType:     accessDataTypeCrypto,
					metadataKeyInstance: instanceName,
				})
		}

		err = adp.validateKeyAccessDataStruct(structData)
		if err != nil {
			return commonErrs.WithMetadata(err,
				map[string]string{
					metadataKeyType:     accessDataTypeCrypto,
					metadataKeyInstance: instanceName,
				})
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
		return nil, commonErrs.NewGrpcErrorWithDetails(
			commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidProtoStruct, nil)
	}

	for instanceName, cryptoAccessDataJson := range cryptoAccessDataMap {
		if instanceName == "" {
			return nil, commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonEmptyInstanceName, nil)
		}

		err = adp.providerProcessor.ValidateJSONData(cryptoAccessDataJson)
		if err != nil {
			return nil, commonErrs.WithMetadata(err,
				map[string]string{
					metadataKeyInstance: instanceName,
				})
		}

		cryptoAccessData := make(map[string]string)
		err = json.Unmarshal(cryptoAccessDataJson, &cryptoAccessData)
		if err != nil {
			return nil, commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidProtoStruct,
				map[string]string{
					metadataKeyInstance: instanceName,
				})
		}

		cryptoAccessProto := adp.providerProcessor.PopulateStructData(nativeKeyID, cryptoAccessData)
		cryptoAccessProtoBytes, err := proto.Marshal(cryptoAccessProto)
		if err != nil {
			return nil, commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidProtoStruct,
				map[string]string{
					metadataKeyInstance: instanceName,
				})
		}
		transformedCryptoAccessDataMap[instanceName] = cryptoAccessProtoBytes
	}

	return transformedCryptoAccessDataMap, nil
}

// validateKeyAccessDataStruct validates the given struct data against the provider.
// This function must always return a gRPC error status if validation fails.
func (adp *AccessDataProcessor) validateKeyAccessDataStruct(data *structpb.Struct) error {
	jsonData, err := protojson.Marshal(data)
	if err != nil {
		return commonErrs.NewGrpcErrorWithDetails(
			commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidProtoStruct, nil,
		)
	}

	return adp.providerProcessor.ValidateJSONData(jsonData)
}
