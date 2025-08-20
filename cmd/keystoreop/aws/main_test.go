package main_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/magodo/slog2hclog"
	"github.com/stretchr/testify/assert"

	kscommonv1 "github.com/openkcm/plugin-sdk/proto/plugin/keystore/common/v1"

	ap "github.com/openkcm/keystore-plugins/cmd/keystoreop/aws"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/clients/aws"
	"github.com/openkcm/keystore-plugins/pkg/keystoreop/clients/aws/mock"
)

var (
	errForced      = errors.New("forced error")
	expectedKeyID  = uuid.New().String()
	now            = time.Now().UTC()
	expectedKeyArn = "arn:aws:kms:us-west-2:123456789012:key/" + expectedKeyID
	happyPathMock  = mock.HappyPathMock(expectedKeyID, expectedKeyArn, now)
	errorMock      = mock.ErrorMock(errForced)
)

func setupTest() *ap.AWSPlugin {
	p := ap.NewAWSPlugin(
		func(ctx context.Context, cfg *kscommonv1.KeystoreInstanceConfig, region string) (*aws.Client, error) {
			return aws.NewClientForTests(happyPathMock), nil
		},
	)
	logLevelPlugin := new(slog.LevelVar)
	logLevelPlugin.Set(slog.LevelError)

	p.SetLogger(slog2hclog.New(slog.Default(), logLevelPlugin))

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
