package main_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"

	aws "github.com/openkcm/cmd/keystoreop/aws"
)

func TestNewAWSClient(t *testing.T) {
	client, err := aws.NewAWSClient(t.Context(), "us-west-2", credentials.NewStaticCredentialsProvider("key", "secret", ""))

	assert.NoError(t, err)
	assert.NotNil(t, client)
}
