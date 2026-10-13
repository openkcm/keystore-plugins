package accessdata

import (
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	awsProto "github.com/openkcm/pkg/proto"
	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
)

const (
	roleRegexPattern        = `^arn:aws:iam::(\d)+:role\/.+$`
	trustAnchorRegexPattern = `^arn:aws:rolesanywhere:[\w-]+:(\d)+:trust-anchor\/[\w-]+$`
	profileRegexPattern     = `^arn:aws:rolesanywhere:[\w-]+:(\d)+:profile\/[\w-]+$`
)

const (
	GrpcErrorReasonInvalidTrustAnchor = "INVALID_TRUST_ANCHOR_ARN"
	GrpcErrorReasonInvalidProfile     = "INVALID_PROFILE_ARN"
	GrpcErrorReasonInvalidRole        = "INVALID_ROLE_ARN"
	GrpcErrorReasonARNAccountMismatch = "ARN_ACCOUNT_MISMATCH"
)

var (
	roleRegex        = regexp.MustCompile(roleRegexPattern)
	trustAnchorRegex = regexp.MustCompile(trustAnchorRegexPattern)
	profileRegex     = regexp.MustCompile(profileRegexPattern)
)

var (
	ErrorCannotParseAccessData = commonErrs.NewGrpcErrorWithDetails(
		commonErrs.StatusInvalidKeyAccessData, commonErrs.ReasonCannotParseData, nil)
	ErrorInvalidTrustAnchor = commonErrs.NewGrpcErrorWithDetails(
		commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidTrustAnchor, nil)
	ErrorInvalidProfile = commonErrs.NewGrpcErrorWithDetails(
		commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidProfile, nil)
	ErrorInvalidRole = commonErrs.NewGrpcErrorWithDetails(
		commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonInvalidRole, nil)
	ErrorARNAccountMismatch = commonErrs.NewGrpcErrorWithDetails(
		commonErrs.StatusInvalidKeyAccessData, GrpcErrorReasonARNAccountMismatch, nil)
)

type AWSAccessDataProcessor struct{}

func NewAWSAccessDataProcessor() *AWSAccessDataProcessor {
	return &AWSAccessDataProcessor{}
}

func (p AWSAccessDataProcessor) Name() string {
	return "AWS"
}

func (p AWSAccessDataProcessor) ValidateJSONData(jsonData []byte) error {
	// Unmarshal JSON into awsProto.AWSKeyAccessData
	var awsData awsProto.AWSKeyAccessData
	err := protojson.Unmarshal(jsonData, &awsData)
	if err != nil {
		return ErrorCannotParseAccessData
	}

	// Validate required fields
	missingFields := make([]string, 0)

	if awsData.TrustAnchorArn == "" {
		missingFields = append(missingFields, "trustAnchorArn")
	}
	if awsData.ProfileArn == "" {
		missingFields = append(missingFields, "profileArn")
	}
	if awsData.RoleArn == "" {
		missingFields = append(missingFields, "roleArn")
	}

	if len(missingFields) > 0 {
		return commonErrs.NewGrpcErrorWithDetails(
			commonErrs.StatusInvalidKeyAccessData, commonErrs.ReasonMissingFields,
			map[string]string{
				commonErrs.MetadataMissingFields: strings.Join(missingFields, ","),
			},
		)
	}

	// Validate ARN formats
	if !trustAnchorRegex.MatchString(awsData.TrustAnchorArn) {
		return ErrorInvalidTrustAnchor
	}

	if !profileRegex.MatchString(awsData.ProfileArn) {
		return ErrorInvalidProfile
	}

	if !roleRegex.MatchString(awsData.RoleArn) {
		return ErrorInvalidRole
	}

	// Validate ARNs belong to the same AWS account
	if !validateARNsFromSameAccount(awsData.TrustAnchorArn, awsData.ProfileArn, awsData.RoleArn) {
		return ErrorARNAccountMismatch
	}

	return nil
}

func (p AWSAccessDataProcessor) PopulateStructData(
	nativeKeyID string,
	cryptoAccessData map[string]string,
) proto.Message {
	accessData := &awsProto.AWSKeyAccessData{
		TrustAnchorArn:     cryptoAccessData["trustAnchorArn"],
		ProfileArn:         cryptoAccessData["profileArn"],
		RoleArn:            cryptoAccessData["roleArn"],
		KeyArn:             nativeKeyID, //nolint:staticcheck
		KeyIdentifier:      nativeKeyID,
		CertificateSubject: cryptoAccessData["certificateSubject"],
	}

	// Populate version info if available
	if versionID, ok := cryptoAccessData["versionIdentifier"]; ok && versionID != "" {
		accessData.VersionIdentifier = versionID
	}

	return accessData
}

func validateARNsFromSameAccount(trustAnchorArn, profileArn, roleArn string) bool {
	accountFromRole := strings.Split(roleArn, ":")[4]
	accountFromTrustAnchor := strings.Split(trustAnchorArn, ":")[4]
	accountFromProfile := strings.Split(profileArn, ":")[4]

	return accountFromRole == accountFromTrustAnchor && accountFromRole == accountFromProfile
}
