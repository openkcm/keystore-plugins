package client

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var (
	PrepareAlias                      = prepareAlias
	CreateKeyInputFromKeyOptions      = createKeyInputFromKeyOptions
	AddRequestHeaders                 = addRequestHeaders
	CreateAuthorizationHeader         = createAuthorizationHeader
	CreateCanonicalAndSignedHeaders   = createCanonicalAndSignedHeaders
	CreateCanonicalQueryString        = createCanonicalQueryString
	CreateStringToSign                = createStringToSign
	GetScope                          = getScope
	GetRolesAnywhereCredentials       = getRolesAnywhereCredentials
	PrepareRequest                    = prepareRequest
	CreateRolesAnywhereSessionFromUrl = createRolesAnywhereSessionFromUrl
	ConvertKeySpecToKeyAlgorithm      = convertKeySpecToKeyAlgorithm
	ConvertKeyStateToBaseKeyState     = convertKeyStateToBaseKeyState
	ConvertToBaseWrapAlgAndHash       = convertToBaseWrapAlgAndHash
)

// ExportedKmsClient - exported aws kms interface
type ExportedKmsClient interface {
	kmsClient
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
