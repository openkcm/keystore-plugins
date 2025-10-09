package aws

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	awsProto "github.com/openkcm/keystore-plugins/pkg/proto"
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
		return fmt.Errorf("%w: failed to parse data to AWSKeyAccessData: %v", ErrInvalidKeyAccessData, err)
	}

	// Validate required fields
	if awsData.TrustAnchorArn == "" {
		return fmt.Errorf("%w: missing trustAnchorArn", ErrInvalidKeyAccessData)
	}

	if awsData.ProfileArn == "" {
		return fmt.Errorf("%w: missing profileArn", ErrInvalidKeyAccessData)
	}

	if awsData.RoleArn == "" {
		return fmt.Errorf("%w: missing roleArn", ErrInvalidKeyAccessData)
	}

	return nil
}

func (p AWSAccessDataProcessor) PopulateStructData(
	nativeKeyID string,
	cryptoAccessData map[string]string,
) proto.Message {
	return &awsProto.AWSKeyAccessData{
		TrustAnchorArn: cryptoAccessData["trustAnchorArn"],
		ProfileArn:     cryptoAccessData["profileArn"],
		RoleArn:        cryptoAccessData["roleArn"],
		KeyArn:         nativeKeyID,
	}
}
