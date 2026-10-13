package accessdata_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/openkcm/internal/aws/plugins/keystoreop/accessdata"
	awsProto "github.com/openkcm/pkg/proto"
	commonErrs "github.com/openkcm/plugin-sdk/pkg/plugin/keystore/errors"
)

func validAWSKeyAccessData() *awsProto.AWSKeyAccessData {
	return &awsProto.AWSKeyAccessData{
		TrustAnchorArn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/ta-1",
		ProfileArn:     "arn:aws:rolesanywhere:us-east-1:123456789012:profile/p-1",
		RoleArn:        "arn:aws:iam::123456789012:role/role-1",
	}
}

func TestValidateJSONData_Valid(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	data, _ := protojson.Marshal(validAWSKeyAccessData())
	err := p.ValidateJSONData(data)
	assert.NoError(t, err)
}

func TestValidateJSONData_MissingFields(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	awsData := &awsProto.AWSKeyAccessData{}
	data, _ := protojson.Marshal(awsData)

	err := p.ValidateJSONData(data)
	assert.Error(t, err)

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, reason, commonErrs.ReasonMissingFields)
}

func TestValidateJSONData_InvalidTrustAnchor(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	awsData := validAWSKeyAccessData()
	awsData.TrustAnchorArn = "invalid"
	data, _ := protojson.Marshal(awsData)

	err := p.ValidateJSONData(data)
	assert.Error(t, err)

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, reason, accessdata.GrpcErrorReasonInvalidTrustAnchor)
}

func TestValidateJSONData_InvalidProfile(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	awsData := validAWSKeyAccessData()
	awsData.ProfileArn = "invalid"
	data, _ := protojson.Marshal(awsData)

	err := p.ValidateJSONData(data)
	assert.Error(t, err)

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, reason, accessdata.GrpcErrorReasonInvalidProfile)
}

func TestValidateJSONData_InvalidRole(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	awsData := validAWSKeyAccessData()
	awsData.RoleArn = "invalid"
	data, _ := protojson.Marshal(awsData)

	err := p.ValidateJSONData(data)
	assert.Error(t, err)

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, reason, accessdata.GrpcErrorReasonInvalidRole)
}

func TestValidateJSONData_AccountMismatch(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	awsData := validAWSKeyAccessData()
	awsData.ProfileArn = strings.Replace(awsData.ProfileArn, "123456789012", "999999999999", 1)

	data, _ := protojson.Marshal(awsData)
	err := p.ValidateJSONData(data)
	assert.Error(t, err)

	reason, _ := commonErrs.GetDetails(err)
	assert.Equal(t, reason, accessdata.GrpcErrorReasonARNAccountMismatch)
}

func TestPopulateStructData(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	cryptoAccessData := map[string]string{
		"trustAnchorArn": "ta",
		"profileArn":     "pr",
		"roleArn":        "ro",
	}
	msg := p.PopulateStructData("keyid", cryptoAccessData)
	awsMsg, ok := msg.(*awsProto.AWSKeyAccessData)
	assert.True(t, ok)
	assert.Equal(t, "ta", awsMsg.TrustAnchorArn)
	assert.Equal(t, "pr", awsMsg.ProfileArn)
	assert.Equal(t, "ro", awsMsg.RoleArn)
	//nolint:staticcheck
	assert.Equal(t, "keyid", awsMsg.KeyArn)
	assert.Empty(t, awsMsg.CertificateSubject)
}

func TestPopulateStructDataWithCertificateSubject(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	cryptoAccessData := map[string]string{
		"trustAnchorArn":     "ta",
		"profileArn":         "pr",
		"roleArn":            "ro",
		"certificateSubject": "CN=default.kms.aws,L=some-locality,OU=Cloud Platform Clients/landscape/subaccount",
	}
	msg := p.PopulateStructData("keyid", cryptoAccessData)
	awsMsg, ok := msg.(*awsProto.AWSKeyAccessData)
	assert.True(t, ok)
	assert.Equal(t, "ta", awsMsg.TrustAnchorArn)
	assert.Equal(t, "pr", awsMsg.ProfileArn)
	assert.Equal(t, "ro", awsMsg.RoleArn)
	//nolint:staticcheck
	assert.Equal(t, "keyid", awsMsg.KeyArn)
	assert.Equal(t, "CN=default.kms.aws,L=some-locality,OU=Cloud Platform Clients/landscape/subaccount", awsMsg.CertificateSubject)
}

func TestPopulateStructDataWithVersionInfo(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	cryptoAccessData := map[string]string{
		"trustAnchorArn":    "ta",
		"profileArn":        "pr",
		"roleArn":           "ro",
		"versionIdentifier": "version-123",
	}
	msg := p.PopulateStructData("keyid", cryptoAccessData)
	awsMsg, ok := msg.(*awsProto.AWSKeyAccessData)
	assert.True(t, ok)
	assert.Equal(t, "ta", awsMsg.TrustAnchorArn)
	assert.Equal(t, "pr", awsMsg.ProfileArn)
	assert.Equal(t, "ro", awsMsg.RoleArn)
	//nolint:staticcheck
	assert.Equal(t, "keyid", awsMsg.KeyArn)

	assert.Equal(t, "keyid", awsMsg.KeyIdentifier)
	assert.Equal(t, "version-123", awsMsg.VersionIdentifier)
}

func TestName(t *testing.T) {
	p := accessdata.NewAWSAccessDataProcessor()
	assert.Equal(t, "AWS", p.Name())
}
