package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/internal/aws/accessdata"
	"github.com/openkcm/internal/aws/rolesanywhere"
	"github.com/openkcm/utils/crypto"
)

// rolesAnywhereSource exchanges the plugin's certificate for credentials and
// caches one session per trust anchor, profile and role.
type rolesAnywhereSource struct {
	clientCert      commoncfg.SourceRef
	privateKey      commoncfg.SourceRef
	trustAnchorArn  string
	profileArn      string
	roleArn         string
	sessionDuration time.Duration
	allowed         allowList
	createSession   createSessionFunc
	now             func() time.Time
	sessions        *lruCache[rolesAnywhereKey, aws.CredentialsProvider]
}

type rolesAnywhereKey struct {
	trustAnchorArn, profileArn, roleArn string
}

type keyMaterial struct {
	clientCert      *x509.Certificate
	intermediateCAs []*x509.Certificate
	privateKey      *rsa.PrivateKey
}

func newRolesAnywhereSource(cfg Config, deps dependencies) (*rolesAnywhereSource, error) {
	ra := cfg.RolesAnywhere

	sessionDuration := ra.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = RoleAnywhereSessionDuration * time.Second
	}

	s := &rolesAnywhereSource{
		clientCert:      ra.ClientCert,
		privateKey:      ra.PrivateKey,
		trustAnchorArn:  ra.TrustAnchorArn,
		profileArn:      ra.ProfileArn,
		roleArn:         ra.RoleArn,
		sessionDuration: sessionDuration,
		allowed:         newAllowList(ra.AllowedRoleArns),
		createSession:   deps.createSession,
		now:             deps.now,
		sessions:        newLRUCache[rolesAnywhereKey, aws.CredentialsProvider](cfg.cacheSize()),
	}

	// Fail fast on an unreadable certificate or key.
	_, err := s.loadKeyMaterial()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *rolesAnywhereSource) method() Method {
	return MethodRolesAnywhere
}

func (s *rolesAnywhereSource) provider(_ context.Context, req Request) (aws.CredentialsProvider, error) {
	key := rolesAnywhereKey{
		trustAnchorArn: requestValue(req, accessdata.FieldTrustAnchorArn, s.trustAnchorArn),
		profileArn:     requestValue(req, accessdata.FieldProfileArn, s.profileArn),
		roleArn:        requestValue(req, accessdata.FieldRoleArn, s.roleArn),
	}

	if key.trustAnchorArn == "" || key.profileArn == "" || key.roleArn == "" {
		return nil, fmt.Errorf("%w: trustAnchorArn, profileArn and roleArn are required",
			ErrCreateRolesAnywhereSession)
	}

	err := s.allowed.check(key.roleArn)
	if err != nil {
		return nil, err
	}

	return s.sessions.getOrCreate(key, func() aws.CredentialsProvider {
		return newCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return s.newSession(ctx, key)
		}))
	}), nil
}

func (s *rolesAnywhereSource) newSession(ctx context.Context, key rolesAnywhereKey) (aws.Credentials, error) {
	material, err := s.loadKeyMaterial()
	if err != nil {
		return aws.Credentials{}, err
	}

	requestTime := s.now().UTC()

	session, err := s.createSession(ctx, rolesanywhere.Params{
		ProfileArn:      key.profileArn,
		RoleArn:         key.roleArn,
		TrustAnchorArn:  key.trustAnchorArn,
		RequestTime:     requestTime,
		PrivateKey:      material.privateKey,
		ClientCert:      material.clientCert,
		IntermediateCAs: material.intermediateCAs,
		SessionDuration: int64(s.sessionDuration.Seconds()),
	})
	if err != nil {
		return aws.Credentials{}, err
	}

	creds := session.Value
	creds.CanExpire = true
	creds.Expires = requestTime.Add(s.sessionDuration)

	return creds, nil
}

// loadKeyMaterial reads and parses the certificate and key. It runs for every
// new session so that rotated files are picked up.
func (s *rolesAnywhereSource) loadKeyMaterial() (keyMaterial, error) {
	clientCertPEM, err := loadSourceRef("rolesAnywhere.clientCert", s.clientCert)
	if err != nil {
		return keyMaterial{}, err
	}

	privateKeyPEM, err := loadSourceRef("rolesAnywhere.privateKey", s.privateKey)
	if err != nil {
		return keyMaterial{}, err
	}

	clientCert, intermediateCAs, err := crypto.LoadCertificates([]byte(clientCertPEM))
	if err != nil {
		return keyMaterial{}, fmt.Errorf("%w: %w: %w", ErrInvalidAuthConfig, ErrLoadCert, err)
	}

	privateKey, err := crypto.LoadRSAPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return keyMaterial{}, fmt.Errorf("%w: %w: %w", ErrInvalidAuthConfig, ErrLoadPrivateKey, err)
	}

	return keyMaterial{clientCert: clientCert, intermediateCAs: intermediateCAs, privateKey: privateKey}, nil
}
