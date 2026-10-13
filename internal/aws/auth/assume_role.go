package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"

	"github.com/openkcm/internal/aws/accessdata"
)

const (
	// FieldExternalID is the request field that overrides the configured STS external ID.
	FieldExternalID = "externalId"

	defaultSessionName = "openkcm-keystore-plugin"
)

// assumeRoleSource assumes the configured or requested role through STS and
// caches one session per role, external ID and STS region.
type assumeRoleSource struct {
	base        aws.CredentialsProvider
	stsClient   stsClientFunc
	stsRegion   string
	roleArn     string
	externalID  string
	sessionName string
	duration    time.Duration
	allowed     allowList
	sessions    *lruCache[assumeRoleKey, aws.CredentialsProvider]
}

type assumeRoleKey struct {
	region, roleArn, externalID string
}

func newAssumeRoleSource(ctx context.Context, cfg Config, deps dependencies) (*assumeRoleSource, error) {
	ar := cfg.AssumeRole
	if ar == nil {
		ar = &AssumeRoleConfig{}
	}

	baseMethod := ar.Source
	if baseMethod == "" {
		baseMethod = MethodAmbient
	}

	base, err := baseCredentials(ctx, baseMethod, cfg.AccessKey, deps)
	if err != nil {
		return nil, err
	}

	externalID, err := loadOptionalSourceRef("assumeRole.externalId", ar.ExternalID)
	if err != nil {
		return nil, err
	}

	sessionName := ar.SessionName
	if sessionName == "" {
		sessionName = defaultSessionName
	}

	return &assumeRoleSource{
		base:        base,
		stsClient:   deps.stsClient,
		stsRegion:   ar.Region,
		roleArn:     ar.RoleArn,
		externalID:  externalID,
		sessionName: sessionName,
		duration:    ar.Duration,
		allowed:     newAllowList(ar.AllowedRoleArns),
		sessions:    newLRUCache[assumeRoleKey, aws.CredentialsProvider](cfg.cacheSize()),
	}, nil
}

func (s *assumeRoleSource) method() Method {
	return MethodAssumeRole
}

func (s *assumeRoleSource) provider(_ context.Context, req Request) (aws.CredentialsProvider, error) {
	key := assumeRoleKey{
		region:     s.stsRegion,
		roleArn:    requestValue(req, accessdata.FieldRoleArn, s.roleArn),
		externalID: requestValue(req, FieldExternalID, s.externalID),
	}

	if key.region == "" {
		key.region = req.Region
	}

	if key.roleArn == "" {
		return nil, fmt.Errorf("%w: no roleArn configured or sent with the request", ErrResolveCredentials)
	}

	err := s.allowed.check(key.roleArn)
	if err != nil {
		return nil, err
	}

	return s.sessions.getOrCreate(key, func() aws.CredentialsProvider {
		return newCredentialsCache(stscreds.NewAssumeRoleProvider(s.stsClient(key.region, s.base), key.roleArn,
			func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = s.sessionName
				o.Duration = s.duration

				if key.externalID != "" {
					o.ExternalID = &key.externalID
				}
			}))
	}), nil
}
