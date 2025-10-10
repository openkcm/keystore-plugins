package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"

	"github.com/openkcm/keystore-plugins/internal/common"
	aws "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	"github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/base"
	"github.com/openkcm/keystore-plugins/internal/utils/ptr"
)

var (
	ErrOperationNotSupported = errors.New("operation not supported")
	ErrInvalidARN            = errors.New("invalid ARN")
	ErrDecodeImportToken     = errors.New("failed to decode import token")
	ErrDecodeKeyMaterial     = errors.New("failed to decode key material")
	ErrInvalidKeyAccessData  = errors.New("invalid AWS key access data")
)

// awsARNPattern is a pattern for AWSPlugin ARN FULL
const (
	awsARNPattern = `^arn:aws:kms:[a-zA-Z0-9-]*:[0-9]*:[a-zA-Z0-9-:/._+<>]*$`
	arnMinParts   = 4
)

var awsRegexPattern = regexp.MustCompile(awsARNPattern)

func extractRegionFromARN(arn string) (string, error) {
	switch {
	// AWSPlugin ARN FULL pattern
	case awsRegexPattern.MatchString(arn):
		parts := strings.Split(arn, ":")

		if len(parts) >= arnMinParts && parts[3] != "" {
			return parts[3], nil
		}

		return "", ErrInvalidARN

	default:
		return "", ErrInvalidARN
	}
}

func (ap *Plugin) getClientFromRequestParams(
	ctx context.Context,
	params *operationsv1.RequestParameters,
) (*aws.Client, error) {
	region, err := extractRegionFromARN(params.KeyId)
	if err != nil {
		return nil, err
	}

	client, err := ap.ClientFactory(ctx, params.Config, region)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// CreateKey implements the CreateKey RPC method
func (ap *Plugin) CreateKey(
	_ context.Context,
	_ *operationsv1.CreateKeyRequest,
) (*operationsv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("%w: %s", ErrOperationNotSupported, "CreateKey is not supported")
}

// DeleteKey implements the DeleteKey RPC method
func (ap *Plugin) DeleteKey(
	_ context.Context,
	_ *operationsv1.DeleteKeyRequest,
) (*operationsv1.DeleteKeyResponse, error) {
	return nil, fmt.Errorf("%w: %s", ErrOperationNotSupported, "DeleteKey is not supported")
}

// EnableKey implements the EnableKey RPC method
func (ap *Plugin) EnableKey(
	_ context.Context,
	_ *operationsv1.EnableKeyRequest,
) (*operationsv1.EnableKeyResponse, error) {
	return nil, fmt.Errorf("%w: %s", ErrOperationNotSupported, "EnableKey is not supported")
}

// DisableKey implements the DisableKey RPC method
func (ap *Plugin) DisableKey(
	_ context.Context,
	_ *operationsv1.DisableKeyRequest,
) (*operationsv1.DisableKeyResponse, error) {
	return nil, fmt.Errorf("%w: %s", ErrOperationNotSupported, "DisableKey is not supported")
}

// GetKey implements the GetKey RPC method
func (ap *Plugin) GetKey(
	ctx context.Context,
	request *operationsv1.GetKeyRequest,
) (*operationsv1.GetKeyResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	result, err := client.GetKey(ctx, request.Parameters.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return &operationsv1.GetKeyResponse{
		KeyId:     result.ID,
		Algorithm: common.ConvertBaseToOperationsKeyAlgorithm(result.KeyAlgorithm),
		Status:    result.Status,
		Usage:     result.Usage,
	}, nil
}

// GetImportParameters implements the GetImportParameters RPC method
func (ap *Plugin) GetImportParameters(
	_ context.Context,
	_ *operationsv1.GetImportParametersRequest,
) (*operationsv1.GetImportParametersResponse, error) {
	return nil, fmt.Errorf("%w: %s", ErrOperationNotSupported, "GetImportParameters is not supported")
}

// ImportKeyMaterial implements the ImportKeyMaterial RPC method
func (ap *Plugin) ImportKeyMaterial(
	_ context.Context,
	_ *operationsv1.ImportKeyMaterialRequest,
) (*operationsv1.ImportKeyMaterialResponse, error) {
	return nil, fmt.Errorf("%w: %s", ErrOperationNotSupported, "ImportKeyMaterial is not supported")
}

func (ap *Plugin) ValidateKey(
	_ context.Context,
	request *operationsv1.ValidateKeyRequest,
) (*operationsv1.ValidateKeyResponse, error) {
	// Validate key type
	if request.KeyType == operationsv1.KeyType_KEY_TYPE_UNSPECIFIED {
		return ptr.PointTo(operationsv1.ValidateKeyResponse{
			IsValid: false,
			Message: "key type must be specified",
		}), nil
	}

	// Validate key algorithm
	if request.Algorithm == operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return ptr.PointTo(operationsv1.ValidateKeyResponse{
			IsValid: false,
			Message: "algorithm must be specified",
		}), nil
	}

	var err error

	region := request.Region

	// Extract region from ARN if KeyType is HYOK
	if request.KeyType == operationsv1.KeyType_KEY_TYPE_HYOK {
		region, err = extractRegionFromARN(request.NativeKeyId)
		if err != nil {
			return ptr.PointTo(operationsv1.ValidateKeyResponse{
				IsValid: false,
				Message: fmt.Sprintf("failed to extract region from ARN: %s, error: %v", request.NativeKeyId, err),
			}), nil
		}
	}

	// Validate region
	if _, ok := validRegions[region]; !ok {
		return ptr.PointTo(operationsv1.ValidateKeyResponse{
			IsValid: false,
			Message: "invalid region: " + request.Region,
		}), nil
	}

	return ptr.PointTo(operationsv1.ValidateKeyResponse{
		IsValid: true,
	}), nil
}

func (ap *Plugin) ValidateKeyAccessData(
	_ context.Context,
	accessData *operationsv1.ValidateKeyAccessDataRequest,
) (*operationsv1.ValidateKeyAccessDataResponse, error) {
	processor := base.NewAccessDataProcessor(NewAWSAccessDataProcessor())

	err := processor.ValidateKeyAccessData(
		accessData.GetManagement(),
		accessData.GetCrypto(),
	)
	if err != nil {
		return ptr.PointTo(operationsv1.ValidateKeyAccessDataResponse{
			IsValid: false,
			Message: err.Error(),
		}), nil
	}

	return ptr.PointTo(operationsv1.ValidateKeyAccessDataResponse{
		IsValid: true,
	}), nil
}

func (ap *Plugin) TransformCryptoAccessData(
	_ context.Context,
	request *operationsv1.TransformCryptoAccessDataRequest,
) (*operationsv1.TransformCryptoAccessDataResponse, error) {
	keyID := request.GetNativeKeyId()
	if keyID == "" {
		return nil, errors.New("AWS key ARN must be present in the keyID field of the request")
	}

	jsonBytes := request.GetAccessData()
	if jsonBytes == nil {
		return nil, errors.New("crypto access data cannot be nil")
	}

	processor := base.NewAccessDataProcessor(NewAWSAccessDataProcessor())

	transformedData, err := processor.TransformCryptoAccessData(keyID, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to transform crypto access data: %w", err)
	}

	return &operationsv1.TransformCryptoAccessDataResponse{
		TransformedAccessData: transformedData,
	}, nil
}

func (ap *Plugin) ExtractKeyRegion(
	_ context.Context,
	request *operationsv1.ExtractKeyRegionRequest,
) (*operationsv1.ExtractKeyRegionResponse, error) {
	if request == nil {
		return nil, errors.New("nil request")
	}

	region, err := extractRegionFromARN(request.NativeKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to extract region from ARN: %s, error: %v", request.NativeKeyId, err)
	}

	return &operationsv1.ExtractKeyRegionResponse{
		Region: region,
	}, nil
}
