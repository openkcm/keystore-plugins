package auth

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/openkcm/internal/common"
)

// perRequestSource implements MethodPerRequest: each request carries authType and
// the matching credentials in its keystore instance configuration.
type perRequestSource struct {
	createSession createSessionFunc
}

func (s *perRequestSource) method() Method {
	return MethodPerRequest
}

func (s *perRequestSource) provider(ctx context.Context, req Request) (aws.CredentialsProvider, error) {
	reader, err := common.NewStructReader(req.Values)
	if err != nil {
		return nil, err
	}

	authType, err := reader.GetString("authType")
	if err != nil {
		return nil, err
	}

	var authMethod AWSAuthMethod

	switch authType {
	case common.AuthTypeSecret:
		authMethod = &SecretAuthMethod{}
	case common.AuthTypeCertificate:
		authMethod = &CertificateAuthMethod{CreateRolesAnywhereSessionFunc: s.createSession}
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAuth, authType)
	}

	cfg, err := authMethod.GetCredentials(ctx, reader)
	if err != nil {
		return nil, err
	}

	sessionToken := ""
	if cfg.SessionToken != nil {
		sessionToken = *cfg.SessionToken
	}

	return credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, sessionToken), nil
}
