package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	awsAccessData "github.com/openkcm/internal/aws/plugins/keystoreop/accessdata"
	"github.com/openkcm/internal/common"
	"github.com/openkcm/internal/common/keystoreop"
	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
	operationsv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/operations/v1"
)

var (
	ErrInvalidARN        = errors.New("invalid ARN")
	ErrDecodeImportToken = errors.New("failed to decode import token")
	ErrDecodeKeyMaterial = errors.New("failed to decode key material")
)

const (
	GrpcErrorReasonUntrustedCert         = "UNTRUSTED_CERTIFICATE"
	GrpcErrorReasonCannotAssumeRole      = "CANNOT_ASSUME_ROLE"
	GrpcErrorReasonTrustAnchorNotFound   = "TRUST_ANCHOR_NOT_FOUND"
	GrpcErrorReasonRoleNotInProfile      = "ROLE_NOT_IN_PROFILE"
	GrpcErrorReasonProfileNotFound       = "PROFILE_NOT_FOUND"
	GrpcErrorReasonDeniedByPolicy        = "DENIED_BY_POLICY"
	GrpcErrorReasonListKeyVersionsDenied = "DENIED_GET_KEY_VERSIONS_BY_POLICY"
	GrpcErrorReasonGenericAuthError      = "AUTHENTICATION_ERROR"
	GrpcErrorReasonRoleNotAllowed        = "ROLE_NOT_ALLOWED"
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

func (ap *AWSPlugin) getClientFromRequestParams(
	ctx context.Context,
	params *operationsv1.RequestParameters,
) (*aws.Client, error) {
	region, err := extractRegionFromARN(params.KeyId)
	if err != nil {
		return nil, err
	}

	client, err := ap.newClient(ctx, params.Config, region)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// CreateKey implements the CreateKey RPC method
func (ap *AWSPlugin) CreateKey(
	ctx context.Context,
	request *operationsv1.CreateKeyRequest,
) (*operationsv1.CreateKeyResponse, error) {
	client, err := ap.newClient(ctx, request.Config, request.Region)
	if err != nil {
		return nil, err
	}

	keyAlgorithm := keystoreop.ConvertOperationsToBaseKeyAlgorithm(request.Algorithm)
	keyType := keystoreop.ConvertOperationsToBaseKeyType(request.GetKeyType())

	keyOutput, err := client.CreateKey(ctx, keystoreop.KeyInput{
		KeyAlgorithm: keyAlgorithm,
		ID:           request.Id,
		KeyType:      keyType,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create key: %w, keyAlgorithm: %s, request algorithm: %s",
			err,
			keyAlgorithm,
			request.Algorithm,
		)
	}

	return &operationsv1.CreateKeyResponse{
		KeyId:  keyOutput.ID,
		Status: keyOutput.Status,
	}, nil
}

// DeleteKey implements the DeleteKey RPC method
func (ap *AWSPlugin) DeleteKey(
	ctx context.Context,
	request *operationsv1.DeleteKeyRequest,
) (*operationsv1.DeleteKeyResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	deleteOptions := keystoreop.DeleteOptions{
		Window: request.Window,
	}

	err = client.DeleteKey(ctx, request.Parameters.KeyId, deleteOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	return &operationsv1.DeleteKeyResponse{}, nil
}

// EnableKey implements the EnableKey RPC method
func (ap *AWSPlugin) EnableKey(
	ctx context.Context,
	request *operationsv1.EnableKeyRequest,
) (*operationsv1.EnableKeyResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	err = client.EnableKey(ctx, request.Parameters.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to enable key: %w", err)
	}

	return &operationsv1.EnableKeyResponse{}, nil
}

// DisableKey implements the DisableKey RPC method
func (ap *AWSPlugin) DisableKey(
	ctx context.Context,
	request *operationsv1.DisableKeyRequest,
) (*operationsv1.DisableKeyResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	err = client.DisableKey(ctx, request.Parameters.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to disable key: %w", err)
	}

	return &operationsv1.DisableKeyResponse{}, nil
}

func (ap *AWSPlugin) GetKeyVersions(
	ctx context.Context,
	request *operationsv1.GetKeyVersionsRequest,
) (*operationsv1.GetKeyVersionsResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	result, err := client.GetKeyVerions(ctx, request.Parameters.KeyId)
	if err != nil {
		ap.logger.Error("failed to get key versions", "error", err, "keyId", request.Parameters.KeyId)
		if errors.Is(err, aws.ErrAccessDenied) {
			return nil, commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusProviderAuthenticationError, GrpcErrorReasonListKeyVersionsDenied, nil,
			)
		}
		return nil, err
	}

	protoVersions := make([]*operationsv1.GetKeyVersionsResponse_KeyVersion, len(result))
	for i, v := range result {
		var creationTime *timestamppb.Timestamp
		if v.CreationTime != nil {
			creationTime = timestamppb.New(*v.CreationTime)
		}
		protoVersions[i] = &operationsv1.GetKeyVersionsResponse_KeyVersion{
			VersionId:    v.ID,
			CreationTime: creationTime,
			Status:       &v.Status,
		}
	}

	return &operationsv1.GetKeyVersionsResponse{
		Versions: protoVersions,
	}, nil
}

// GetKey implements the GetKey RPC method
func (ap *AWSPlugin) GetKey(
	ctx context.Context,
	request *operationsv1.GetKeyRequest,
) (*operationsv1.GetKeyResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	result, err := client.GetKey(ctx, request.Parameters.KeyId)
	if err != nil {
		ap.logger.Error("failed to get key", "error", err, "keyId", request.Parameters.KeyId)
		switch {
		case errors.Is(err, aws.ErrNativeKeyNotFound):
			return nil, commonErrs.StatusKeyNotFound.Err()
		case errors.Is(err, aws.ErrAccessDenied):
			return nil, commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusProviderAuthenticationError, GrpcErrorReasonDeniedByPolicy, nil,
			)
		default:
			return nil, commonErrs.NewGrpcErrorWithDetails(commonErrs.StatusKeyGenericErr, err.Error(), nil)
		}
	}

	var rotationTimestamp *timestamppb.Timestamp
	if result.RotationTime != nil {
		rotationTimestamp = timestamppb.New(*result.RotationTime)
	}
	return &operationsv1.GetKeyResponse{
		KeyId:              result.ID,
		Algorithm:          keystoreop.ConvertBaseToOperationsKeyAlgorithm(result.KeyAlgorithm),
		Status:             result.Status,
		Usage:              result.Usage,
		LatestKeyVersionId: result.CurrentVersionID,
		LatestRotationTime: rotationTimestamp,
	}, nil
}

// GetImportParameters implements the GetImportParameters RPC method
func (ap *AWSPlugin) GetImportParameters(
	ctx context.Context,
	request *operationsv1.GetImportParametersRequest,
) (*operationsv1.GetImportParametersResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	keyAlgorithm := keystoreop.ConvertOperationsToBaseKeyAlgorithm(request.Algorithm)
	importParams, err := client.GetImportParameters(ctx, request.Parameters.KeyId, keyAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get import parameters: %w", err)
	}

	importParametersStruct, err := structpb.NewStruct(map[string]any{
		"keyID":             importParams.ID,
		"publicKey":         importParams.PublicKey,
		"providerParams":    importParams.ProviderParams,
		"validTo":           importParams.ValidTo,
		"wrappingAlgorithm": importParams.WrappingAlgorithm,
		"hashFunction":      importParams.HashFunction,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create import parameters struct: %w", err)
	}

	return &operationsv1.GetImportParametersResponse{
		KeyId:            importParams.ID,
		ImportParameters: importParametersStruct,
	}, nil
}

// ImportKeyMaterial implements the ImportKeyMaterial RPC method
func (ap *AWSPlugin) ImportKeyMaterial(
	ctx context.Context,
	request *operationsv1.ImportKeyMaterialRequest,
) (*operationsv1.ImportKeyMaterialResponse, error) {
	client, err := ap.getClientFromRequestParams(ctx, request.Parameters)
	if err != nil {
		return nil, err
	}

	reader, err := common.NewStructReader(request.ImportParameters)
	if err != nil {
		return nil, err
	}

	importToken, err := reader.GetString("providerParams")
	if err != nil {
		return nil, err
	}

	importTokenBytes, err := base64.StdEncoding.DecodeString(importToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeImportToken, err)
	}

	keyMaterialBytes, err := base64.StdEncoding.DecodeString(request.EncryptedKeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeKeyMaterial, err)
	}

	err = client.ImportKeyMaterial(
		ctx,
		request.Parameters.KeyId,
		importTokenBytes,
		keyMaterialBytes,
	)
	if err != nil {
		if errors.Is(err, aws.ErrInvalidKeyMaterial) {
			ap.logger.Error("failed to import key material: invalid ciphertext", "error", err, "keyId", request.Parameters.KeyId)
			return nil, commonErrs.NewGrpcErrorWithDetails(
				commonErrs.StatusImportKeyMaterialFailed,
				err.Error(),
				nil,
			)
		}
		return nil, fmt.Errorf("failed to import key material: %w", err)
	}

	return &operationsv1.ImportKeyMaterialResponse{}, nil
}

func (ap *AWSPlugin) ValidateKey(
	_ context.Context,
	request *operationsv1.ValidateKeyRequest,
) (*operationsv1.ValidateKeyResponse, error) {
	// Validate key type
	if request.KeyType == operationsv1.KeyType_KEY_TYPE_UNSPECIFIED {
		return new(operationsv1.ValidateKeyResponse{
			IsValid: false,
			Message: "key type must be specified",
		}), nil
	}

	// Validate key algorithm
	if request.Algorithm == operationsv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return new(operationsv1.ValidateKeyResponse{
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
			return new(operationsv1.ValidateKeyResponse{
				IsValid: false,
				Message: fmt.Sprintf("failed to extract region from ARN: %s, error: %v", request.NativeKeyId, err),
			}), nil
		}
	}

	// Validate region
	if _, ok := validRegions[region]; !ok {
		return new(operationsv1.ValidateKeyResponse{
			IsValid: false,
			Message: "invalid region: " + request.Region,
		}), nil
	}

	return new(operationsv1.ValidateKeyResponse{
		IsValid: true,
	}), nil
}

func (ap *AWSPlugin) ValidateKeyAccessData(
	_ context.Context,
	accessData *operationsv1.ValidateKeyAccessDataRequest,
) (*operationsv1.ValidateKeyAccessDataResponse, error) {
	processor := keystoreop.NewAccessDataProcessor(awsAccessData.NewAWSAccessDataProcessor())
	err := processor.ValidateKeyAccessData(
		accessData.GetManagement(),
		accessData.GetCrypto(),
	)
	if err != nil {
		return new(operationsv1.ValidateKeyAccessDataResponse{
			IsValid: false,
		}), err
	}

	return new(operationsv1.ValidateKeyAccessDataResponse{
		IsValid: true,
	}), nil
}

func (ap *AWSPlugin) TransformCryptoAccessData(
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

	processor := keystoreop.NewAccessDataProcessor(awsAccessData.NewAWSAccessDataProcessor())
	transformedData, err := processor.TransformCryptoAccessData(keyID, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to transform crypto access data: %w", err)
	}
	return &operationsv1.TransformCryptoAccessDataResponse{
		TransformedAccessData: transformedData,
	}, nil
}

func (ap *AWSPlugin) ExtractKeyRegion(
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

func (ap *AWSPlugin) mapRolesAnywhereErrorReason(err error) string {
	switch {
	case strings.Contains(err.Error(), "Untrusted signing certificate"):
		return GrpcErrorReasonUntrustedCert
	case strings.Contains(err.Error(), "Unable to assume role"):
		return GrpcErrorReasonCannotAssumeRole
	case strings.Contains(err.Error(), "Specified Trust Anchor wasn't found"):
		return GrpcErrorReasonTrustAnchorNotFound
	case strings.Contains(err.Error(), "Requested Role isn't one of those listed in the Profile"):
		return GrpcErrorReasonRoleNotInProfile
	case strings.Contains(err.Error(), "Invalid or empty profile provided"):
		return GrpcErrorReasonProfileNotFound
	}
	ap.logger.Warn("Unknown Roles Anywhere authentication error: %v", err)
	return GrpcErrorReasonGenericAuthError
}
