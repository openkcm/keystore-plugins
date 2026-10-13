package auth_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/internal/aws/auth"
	"github.com/openkcm/internal/aws/rolesanywhere"
	"github.com/openkcm/internal/common"
	"github.com/openkcm/utils/testcerts"
)

const (
	testRoleArn        = "arn:aws:iam::123456789012:role/openkcm-tenant"
	testTrustAnchorArn = "arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/ta"
	testProfileArn     = "arn:aws:rolesanywhere:eu-west-1:123456789012:profile/p"
)

var errTest = errors.New("test error")

func embedded(value string) commoncfg.SourceRef {
	return commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: value}
}

func values(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()

	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}

	return s
}

func accessKeyConfig() *auth.AccessKeyConfig {
	return &auth.AccessKeyConfig{AccessKeyID: embedded("plugin-key"), SecretAccessKey: embedded("plugin-secret")}
}

func mustNew(t *testing.T, cfg auth.Config, opts ...auth.Option) auth.Source {
	t.Helper()

	source, err := auth.New(t.Context(), cfg, opts...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	return source
}

func retrieve(t *testing.T, source auth.Source, req auth.Request) (aws.Credentials, error) {
	t.Helper()

	provider, err := source.Credentials(t.Context(), req)
	if err != nil {
		return aws.Credentials{}, err
	}

	return provider.Retrieve(t.Context())
}

func TestDecodeConfig(t *testing.T) {
	decode := func(t *testing.T, doc string) (auth.Config, error) {
		t.Helper()

		var node yaml.Node
		if err := yaml.Unmarshal([]byte(doc), &node); err != nil {
			t.Fatal(err)
		}

		return auth.DecodeConfig(node.Content[0])
	}

	t.Run("Full", func(t *testing.T) {
		cfg, err := decode(t, `
method: assumeRole
cacheSize: 10
assumeRole:
  region: eu-central-1
  roleArn: `+testRoleArn+`
  duration: 1h
  allowedRoleArns: ["arn:aws:iam::*:role/openkcm-*"]
`)

		assert.NoError(t, err)
		assert.Equal(t, auth.MethodAssumeRole, cfg.Method)
		assert.Equal(t, 10, cfg.CacheSize)
		assert.Equal(t, time.Hour, cfg.AssumeRole.Duration)
		assert.Equal(t, "eu-central-1", cfg.AssumeRole.Region)
	})

	t.Run("UnknownField", func(t *testing.T) {
		_, err := decode(t, "method: accessKey\nstatic:\n  accesKeyId: {value: x}\n")

		assert.ErrorIs(t, err, auth.ErrInvalidAuthConfig)
	})

	t.Run("Nil", func(t *testing.T) {
		cfg, err := auth.DecodeConfig(nil)

		assert.NoError(t, err)
		assert.Empty(t, cfg.Method)
	})
}

func TestNew_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  auth.Config
	}{
		{"UnknownMethod", auth.Config{Method: "magic"}},
		{"NegativeCacheSize", auth.Config{Method: auth.MethodAmbient, CacheSize: -1}},
		{"StaticWithoutSection", auth.Config{Method: auth.MethodAccessKey}},
		{"StaticMissingSecret", auth.Config{Method: auth.MethodAccessKey, AccessKey: &auth.AccessKeyConfig{AccessKeyID: embedded("k")}}},
		{"StaticUnsetEnv", auth.Config{Method: auth.MethodAccessKey, AccessKey: &auth.AccessKeyConfig{
			AccessKeyID:     commoncfg.SourceRef{Source: commoncfg.EnvSourceValue, Env: "AWS_PLUGIN_TEST_UNSET"},
			SecretAccessKey: embedded("s"),
		}}},
		{"AssumeRoleUnknownSource", auth.Config{Method: auth.MethodAssumeRole, AssumeRole: &auth.AssumeRoleConfig{Source: "magic"}}},
		{"AssumeRoleStaticWithoutSection", auth.Config{
			Method: auth.MethodAssumeRole, AssumeRole: &auth.AssumeRoleConfig{Source: auth.MethodAccessKey},
		}},
		{"AssumeRoleBadSessionName", auth.Config{Method: auth.MethodAssumeRole, AssumeRole: &auth.AssumeRoleConfig{SessionName: "bad name"}}},
		{"AssumeRoleDurationTooLong", auth.Config{Method: auth.MethodAssumeRole, AssumeRole: &auth.AssumeRoleConfig{Duration: 13 * time.Hour}}},
		{"AssumeRoleEmptyPattern", auth.Config{Method: auth.MethodAssumeRole, AssumeRole: &auth.AssumeRoleConfig{AllowedRoleArns: []string{" "}}}},
		{"AssumeRoleEmptyExternalID", auth.Config{Method: auth.MethodAssumeRole, AccessKey: accessKeyConfig(), AssumeRole: &auth.AssumeRoleConfig{
			Source: auth.MethodAccessKey, ExternalID: &commoncfg.SourceRef{},
		}}},
		{"RolesAnywhereWithoutSection", auth.Config{Method: auth.MethodRolesAnywhere}},
		{"RolesAnywhereDurationTooShort", auth.Config{Method: auth.MethodRolesAnywhere, RolesAnywhere: &auth.RolesAnywhereConfig{
			SessionDuration: time.Minute,
		}}},
		{"RolesAnywhereEmptyPattern", auth.Config{Method: auth.MethodRolesAnywhere, RolesAnywhere: &auth.RolesAnywhereConfig{
			AllowedRoleArns: []string{""},
		}}},
		{"RolesAnywhereMissingKey", auth.Config{Method: auth.MethodRolesAnywhere, RolesAnywhere: &auth.RolesAnywhereConfig{
			ClientCert: embedded("cert"),
		}}},
		{"RolesAnywhereInvalidCert", auth.Config{Method: auth.MethodRolesAnywhere, RolesAnywhere: &auth.RolesAnywhereConfig{
			ClientCert: embedded("not a cert"), PrivateKey: embedded("not a key"),
		}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := auth.New(t.Context(), tt.cfg)

			assert.ErrorIs(t, err, auth.ErrInvalidAuthConfig)
			assert.Nil(t, source)
		})
	}

	t.Run("RolesAnywhereInvalidKey", func(t *testing.T) {
		_, certPEM := testcerts.NewKeyAndCertPEM(t)

		_, err := auth.New(t.Context(), auth.Config{Method: auth.MethodRolesAnywhere, RolesAnywhere: &auth.RolesAnywhereConfig{
			ClientCert: embedded(certPEM), PrivateKey: embedded("not a key"),
		}})

		assert.ErrorIs(t, err, auth.ErrLoadPrivateKey)
	})
}

func TestRequestSource(t *testing.T) {
	for _, method := range []auth.Method{"", auth.MethodPerRequest} {
		source := mustNew(t, auth.Config{Method: method})
		assert.Equal(t, auth.MethodPerRequest, source.Method())
	}

	assert.Equal(t, auth.MethodPerRequest, auth.NewPerRequestSource().Method())

	source := mustNew(t, auth.Config{})

	t.Run("Secret", func(t *testing.T) {
		creds, err := retrieve(t, source, auth.Request{Values: values(t, map[string]any{
			"authType": common.AuthTypeSecret, "accessKeyId": "req-key", "secretAccessKey": "req-secret", "sessionToken": "tok",
		})})

		assert.NoError(t, err)
		assert.Equal(t, "req-key", creds.AccessKeyID)
		assert.Equal(t, "tok", creds.SessionToken)
	})

	t.Run("Certificate", func(t *testing.T) {
		keyPEM, certPEM := testcerts.NewKeyAndCertPEM(t)
		source := mustNew(t, auth.Config{}, auth.WithRolesAnywhereSession(
			func(context.Context, rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error) {
				p := credentials.NewStaticCredentialsProvider("ra-key", "ra-secret", "ra-token")
				return &p, nil
			}))

		creds, err := retrieve(t, source, auth.Request{Values: values(t, map[string]any{
			"authType": common.AuthTypeCertificate, "roleArn": testRoleArn, "trustAnchorArn": testTrustAnchorArn,
			"profileArn": testProfileArn, "clientCert": certPEM, "privateKey": keyPEM,
		})})

		assert.NoError(t, err)
		assert.Equal(t, "ra-key", creds.AccessKeyID)
	})

	errorCases := map[string]*structpb.Struct{
		"NilValues":       nil,
		"MissingAuthType": values(t, map[string]any{}),
		"UnknownAuthType": values(t, map[string]any{"authType": "AUTH_TYPE_MAGIC"}),
		"MissingSecret":   values(t, map[string]any{"authType": common.AuthTypeSecret, "accessKeyId": "k"}),
	}
	for name, v := range errorCases {
		t.Run(name, func(t *testing.T) {
			_, err := retrieve(t, source, auth.Request{Values: v})

			assert.Error(t, err)
		})
	}
}

func TestStaticSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AWS_PLUGIN_TEST_KEY", "env-key")

	source := mustNew(t, auth.Config{Method: auth.MethodAccessKey, AccessKey: &auth.AccessKeyConfig{
		AccessKeyID:     commoncfg.SourceRef{Source: commoncfg.EnvSourceValue, Env: "AWS_PLUGIN_TEST_KEY"},
		SecretAccessKey: commoncfg.SourceRef{Source: commoncfg.FileSourceValue, File: commoncfg.CredentialFile{Path: path}},
		SessionToken:    &commoncfg.SourceRef{Value: "inline-token"},
	}})

	// Credentials sent with the request are ignored.
	creds, err := retrieve(t, source, auth.Request{Values: values(t, map[string]any{"accessKeyId": "req-key"})})

	assert.NoError(t, err)
	assert.Equal(t, auth.MethodAccessKey, source.Method())
	assert.Equal(t, "env-key", creds.AccessKeyID)
	assert.Equal(t, "file-secret", creds.SecretAccessKey)
	assert.Equal(t, "inline-token", creds.SessionToken)
}

func isolateDefaultChain(t *testing.T) {
	t.Helper()

	t.Setenv("AWS_ACCESS_KEY_ID", "chain-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "chain-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
}

func TestDefaultChainSource(t *testing.T) {
	isolateDefaultChain(t)

	source := mustNew(t, auth.Config{Method: auth.MethodAmbient})
	creds, err := retrieve(t, source, auth.Request{Region: "eu-west-1"})

	assert.NoError(t, err)
	assert.Equal(t, "chain-key", creds.AccessKeyID)

	t.Run("RetrieveError", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")

		source := mustNew(t, auth.Config{Method: auth.MethodAmbient})
		_, err := source.Credentials(t.Context(), auth.Request{Region: "eu-west-1"})

		assert.ErrorIs(t, err, auth.ErrResolveCredentials)
	})

	t.Run("InvalidSharedConfig", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "missing-profile")

		_, err := auth.New(t.Context(), auth.Config{Method: auth.MethodAmbient})

		assert.ErrorIs(t, err, auth.ErrInvalidAuthConfig)
	})
}
