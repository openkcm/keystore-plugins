package main_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"

	ap "github.com/openkcm/cmd/keystoreop/aws"
	aws "github.com/openkcm/internal/aws/plugins/keystoreop"
	"github.com/openkcm/internal/aws/plugins/keystoreop/mock"
	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"
)

var (
	errForced      = errors.New("forced error")
	expectedID     = uuid.New().String()
	expectedKeyID  = uuid.New().String()
	now            = time.Now().UTC()
	expectedKeyArn = "arn:aws:kms:us-west-2:123456789012:key/" + expectedKeyID
	happyPathMock  = mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	errorMock      = mock.ErrorMock(errForced)
	buildInfo      = "{}"
)

func setupTest() *ap.AWSPlugin {
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(happyPathMock), nil
		},
		buildInfo,
	)
	p.SetLogger(hclog.New(&hclog.LoggerOptions{Level: hclog.Error, Name: "test"}))
	return p
}

func TestNewAWS(t *testing.T) {
	p := setupTest()
	assert.NotNil(t, p)
}

func TestConfigure(t *testing.T) {
	p := setupTest()
	res, err := p.Configure(context.Background(), nil)

	if err != nil {
		t.Errorf("Configure() error = %v, want nil", err)
	}
	if res == nil {
		t.Errorf("Configure() = nil, want non-nil")
	}
}
