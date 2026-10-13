package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/internal/aws/rolesanywhere"
)

// credentialsExpiryWindow refreshes cached credentials this long before they expire.
const credentialsExpiryWindow = 5 * time.Minute

// Request holds the per-request inputs used to resolve credentials.
type Request struct {
	// Region of the AWS resource being accessed.
	Region string
	// Values is the keystore instance configuration sent with the request. It
	// may be nil.
	Values *structpb.Struct
}

// Source resolves AWS credentials for a request.
type Source interface {
	// Method reports the configured authentication method.
	Method() Method
	// Credentials returns a provider whose credentials have already been
	// retrieved once, so authentication errors surface here rather than on
	// the first AWS call.
	Credentials(ctx context.Context, req Request) (aws.CredentialsProvider, error)
}

// Option customizes how a Source reaches AWS. It exists for tests.
type Option func(*dependencies)

type (
	stsClientFunc     func(region string, creds aws.CredentialsProvider) stscreds.AssumeRoleAPIClient
	createSessionFunc func(ctx context.Context, params rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error)
)

type dependencies struct {
	stsClient         stsClientFunc
	createSession     createSessionFunc
	loadDefaultConfig func(ctx context.Context) (aws.Config, error)
	now               func() time.Time
}

// WithSTSClient replaces the STS client used by MethodAssumeRole.
func WithSTSClient(f func(region string, creds aws.CredentialsProvider) stscreds.AssumeRoleAPIClient) Option {
	return func(d *dependencies) { d.stsClient = f }
}

// WithRolesAnywhereSession replaces the call that creates Roles Anywhere sessions.
func WithRolesAnywhereSession(
	f func(ctx context.Context, params rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error),
) Option {
	return func(d *dependencies) { d.createSession = f }
}

// WithClock replaces the clock used to stamp Roles Anywhere requests.
func WithClock(now func() time.Time) Option {
	return func(d *dependencies) { d.now = now }
}

// sourceImpl is implemented by each authentication method.
type sourceImpl interface {
	method() Method
	provider(ctx context.Context, req Request) (aws.CredentialsProvider, error)
}

// New validates cfg, loads its secrets and returns the Source for its method,
// so configuration mistakes surface when the plugin is configured rather than
// on the first request.
func New(ctx context.Context, cfg Config, opts ...Option) (Source, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	deps := newDependencies(opts)

	var impl sourceImpl

	switch cfg.Method {
	case "", MethodPerRequest:
		impl = &perRequestSource{createSession: deps.createSession}
	case MethodAmbient, MethodAccessKey:
		impl, err = newBaseSource(ctx, cfg.Method, cfg.AccessKey, deps)
	case MethodAssumeRole:
		impl, err = newAssumeRoleSource(ctx, cfg, deps)
	case MethodRolesAnywhere:
		impl, err = newRolesAnywhereSource(cfg, deps)
	}

	if err != nil {
		return nil, err
	}

	return &source{impl: impl}, nil
}

// NewPerRequestSource returns the MethodPerRequest Source, which needs no
// configuration and therefore cannot fail.
func NewPerRequestSource(opts ...Option) Source {
	return &source{impl: &perRequestSource{createSession: newDependencies(opts).createSession}}
}

func newDependencies(opts []Option) dependencies {
	deps := dependencies{
		stsClient: func(region string, creds aws.CredentialsProvider) stscreds.AssumeRoleAPIClient {
			return sts.New(sts.Options{Region: region, Credentials: creds})
		},
		createSession: rolesanywhere.CreateSession,
		loadDefaultConfig: func(ctx context.Context) (aws.Config, error) {
			return config.LoadDefaultConfig(ctx)
		},
		now: time.Now,
	}

	for _, opt := range opts {
		opt(&deps)
	}

	return deps
}

// source adds the eager retrieval and error classification shared by all methods.
type source struct {
	impl sourceImpl
}

func (s *source) Method() Method {
	return s.impl.method()
}

func (s *source) Credentials(ctx context.Context, req Request) (aws.CredentialsProvider, error) {
	provider, err := s.impl.provider(ctx, req)
	if err != nil {
		return nil, err
	}

	_, err = provider.Retrieve(ctx)
	if err != nil {
		if s.impl.method() == MethodRolesAnywhere {
			return nil, fmt.Errorf("%w: %w", ErrCreateRolesAnywhereSession, err)
		}

		return nil, fmt.Errorf("%w: %w", ErrResolveCredentials, err)
	}

	return provider, nil
}

// requestValue returns the request's value for key, or fallback when absent.
func requestValue(req Request, key, fallback string) string {
	if value := req.Values.GetFields()[key].GetStringValue(); value != "" {
		return value
	}

	return fallback
}

func newCredentialsCache(provider aws.CredentialsProvider) aws.CredentialsProvider {
	return aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
		o.ExpiryWindow = credentialsExpiryWindow
	})
}
