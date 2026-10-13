package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var (
	PrepareAlias                                    = prepareAlias
	CreateKeyInputFromKeyOptions                    = createKeyInputFromKeyOptions
	CreateScheduleKeyDeletionInputFromDeleteOptions = createScheduleKeyDeletionInputFromDeleteOptions
	ConvertKeySpecToKeyAlgorithm                    = convertKeySpecToKeyAlgorithm
	ConvertKeyStateToBaseKeyState                   = convertKeyStateToBaseKeyState
	ConvertToBaseWrapAlgAndHash                     = convertToBaseWrapAlgAndHash
)

// ExportedKmsClient - exported aws kms interface
type ExportedKmsClient interface {
	kmsClient
}

// ExportUpdateAlias - exported update alias function
func (c *Client) ExportUpdateAlias() func(ctx context.Context, keyID string, aliasName string) error {
	return c.updateAlias
}

// ExportCreateAlias - exported create alias function
func (c *Client) ExportCreateAlias() func(ctx context.Context, keyID string, aliasName string) error {
	return c.createAlias
}

// ExportEnsureAlias - exported ensure alias function
func (c *Client) ExportEnsureAlias() func(ctx context.Context, keyID string, aliasName string) error {
	return c.ensureAlias
}

// ExportInternalClientForTests - exported internalClient
func (c *Client) ExportInternalClientForTests(t *testing.T) *kms.Client {
	t.Helper()

	internalClient, ok := c.internalClient.(*kms.Client)
	if !ok {
		t.Fatalf("expected *kms.Client, got %T", c.internalClient)
	}

	return internalClient
}
