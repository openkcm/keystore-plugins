package auth_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/internal/aws/auth"
	"github.com/openkcm/internal/aws/rolesanywhere"
	"github.com/openkcm/utils/testcerts"
)

type fakeSTS struct {
	mu      sync.Mutex
	inputs  []*sts.AssumeRoleInput
	regions []string
	err     error
}

func (f *fakeSTS) client(region string, _ aws.CredentialsProvider) stscreds.AssumeRoleAPIClient {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.regions = append(f.regions, region)

	return f
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}

	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("assumed-" + aws.ToString(in.RoleArn)),
		SecretAccessKey: aws.String("assumed-secret"),
		SessionToken:    aws.String("assumed-token"),
		Expiration:      aws.Time(time.Now().Add(time.Hour)),
	}}, nil
}

func assumeRoleSource(t *testing.T, fake *fakeSTS, ar *auth.AssumeRoleConfig, cacheSize int) auth.Source {
	t.Helper()

	ar.Source = auth.MethodAccessKey

	return mustNew(t, auth.Config{
		Method: auth.MethodAssumeRole, CacheSize: cacheSize, AccessKey: accessKeyConfig(), AssumeRole: ar,
	}, auth.WithSTSClient(fake.client))
}

func TestAssumeRoleSource(t *testing.T) {
	t.Run("ConfiguredRoleIsCachedPerRegion", func(t *testing.T) {
		fake := &fakeSTS{}
		source := assumeRoleSource(t, fake, &auth.AssumeRoleConfig{
			RoleArn: testRoleArn, ExternalID: &commoncfg.SourceRef{Value: "ext"}, Duration: 30 * time.Minute,
		}, 0)

		for range 3 {
			creds, err := retrieve(t, source, auth.Request{Region: "eu-west-1"})
			assert.NoError(t, err)
			assert.Equal(t, "assumed-"+testRoleArn, creds.AccessKeyID)
		}

		_, err := retrieve(t, source, auth.Request{Region: "us-east-1"})
		assert.NoError(t, err)

		assert.Equal(t, []string{"eu-west-1", "us-east-1"}, fake.regions)
		assert.Len(t, fake.inputs, 2)
		assert.Equal(t, "ext", aws.ToString(fake.inputs[0].ExternalId))
		assert.Equal(t, "openkcm-keystore-plugin", aws.ToString(fake.inputs[0].RoleSessionName))
		assert.Equal(t, int32(1800), aws.ToInt32(fake.inputs[0].DurationSeconds))
	})

	t.Run("FixedSTSRegionSharesSessions", func(t *testing.T) {
		fake := &fakeSTS{}
		source := assumeRoleSource(t, fake, &auth.AssumeRoleConfig{RoleArn: testRoleArn, Region: "eu-central-1"}, 0)

		for _, region := range []string{"eu-west-1", "us-east-1"} {
			_, err := retrieve(t, source, auth.Request{Region: region})
			assert.NoError(t, err)
		}

		assert.Equal(t, []string{"eu-central-1"}, fake.regions)
	})

	t.Run("RequestOverridesRoleAndExternalID", func(t *testing.T) {
		fake := &fakeSTS{}
		source := assumeRoleSource(t, fake, &auth.AssumeRoleConfig{
			RoleArn: "arn:aws:iam::1:role/default", SessionName: "custom",
		}, 0)

		_, err := retrieve(t, source, auth.Request{Region: "eu-west-1", Values: values(t, map[string]any{
			"roleArn": testRoleArn, "externalId": "tenant-ext",
		})})

		assert.NoError(t, err)
		assert.Equal(t, testRoleArn, aws.ToString(fake.inputs[0].RoleArn))
		assert.Equal(t, "tenant-ext", aws.ToString(fake.inputs[0].ExternalId))
		assert.Equal(t, "custom", aws.ToString(fake.inputs[0].RoleSessionName))
	})

	t.Run("AllowList", func(t *testing.T) {
		fake := &fakeSTS{}
		source := assumeRoleSource(t, fake, &auth.AssumeRoleConfig{
			AllowedRoleArns: []string{"arn:aws:iam::123456789012:role/openkcm-*"},
		}, 0)

		_, err := retrieve(t, source, auth.Request{Values: values(t, map[string]any{"roleArn": testRoleArn})})
		assert.NoError(t, err)

		_, err = retrieve(t, source, auth.Request{Values: values(t, map[string]any{
			"roleArn": "arn:aws:iam::123456789012:role/admin",
		})})
		assert.ErrorIs(t, err, auth.ErrRoleNotAllowed)
		assert.ErrorIs(t, err, auth.ErrResolveCredentials)
		assert.Len(t, fake.inputs, 1)
	})

	t.Run("CacheEvictsLeastRecentlyUsed", func(t *testing.T) {
		fake := &fakeSTS{}
		source := assumeRoleSource(t, fake, &auth.AssumeRoleConfig{}, 2)
		role := func(n int) auth.Request {
			return auth.Request{Values: values(t, map[string]any{"roleArn": fmt.Sprintf("arn:aws:iam::1:role/r%d", n)})}
		}

		for _, n := range []int{1, 2, 1, 3, 1, 2} { // r2 is evicted by r3, then requested again
			_, err := retrieve(t, source, role(n))
			assert.NoError(t, err)
		}

		assert.Len(t, fake.inputs, 4) // r1, r2, r3, r2 again
	})

	t.Run("MissingRole", func(t *testing.T) {
		source := assumeRoleSource(t, &fakeSTS{}, &auth.AssumeRoleConfig{}, 0)

		_, err := source.Credentials(t.Context(), auth.Request{})

		assert.ErrorIs(t, err, auth.ErrResolveCredentials)
	})

	t.Run("STSError", func(t *testing.T) {
		source := assumeRoleSource(t, &fakeSTS{err: errTest}, &auth.AssumeRoleConfig{RoleArn: testRoleArn}, 0)

		_, err := source.Credentials(t.Context(), auth.Request{})

		assert.ErrorIs(t, err, auth.ErrResolveCredentials)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("DefaultChainBaseAndRealSTSClient", func(t *testing.T) {
		isolateDefaultChain(t)

		source := mustNew(t, auth.Config{Method: auth.MethodAssumeRole})

		_, err := source.Credentials(t.Context(), auth.Request{Region: "eu-west-1"})
		assert.ErrorIs(t, err, auth.ErrResolveCredentials) // no role configured
		assert.Equal(t, auth.MethodAssumeRole, source.Method())
	})
}

// fixedNow is close to the real time because the SDK credentials cache checks
// expiry against the wall clock.
var fixedNow = time.Now().UTC().Truncate(time.Second)

type fakeSessions struct {
	mu     sync.Mutex
	params []rolesanywhere.Params
	err    error
}

func (f *fakeSessions) create(_ context.Context, p rolesanywhere.Params) (*credentials.StaticCredentialsProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.params = append(f.params, p)
	if f.err != nil {
		return nil, f.err
	}

	provider := credentials.NewStaticCredentialsProvider("ra-key", "ra-secret", "ra-token")

	return &provider, nil
}

// writeKeyPair writes a fresh certificate and key and returns file refs to them.
func writeKeyPair(t *testing.T, dir string) (commoncfg.SourceRef, commoncfg.SourceRef) {
	t.Helper()

	keyPEM, certPEM := testcerts.NewKeyAndCertPEM(t)
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")

	for path, content := range map[string]string{certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	file := func(path string) commoncfg.SourceRef {
		return commoncfg.SourceRef{Source: commoncfg.FileSourceValue, File: commoncfg.CredentialFile{Path: path}}
	}

	return file(certPath), file(keyPath)
}

func rolesAnywhereSource(t *testing.T, fake *fakeSessions, ra *auth.RolesAnywhereConfig) auth.Source {
	t.Helper()

	if ra.ClientCert.Source == "" {
		ra.ClientCert, ra.PrivateKey = writeKeyPair(t, t.TempDir())
	}

	now := fixedNow

	return mustNew(t, auth.Config{Method: auth.MethodRolesAnywhere, RolesAnywhere: ra},
		auth.WithRolesAnywhereSession(fake.create), auth.WithClock(func() time.Time { return now }))
}

func TestRolesAnywhereSource(t *testing.T) {
	requestARNs := map[string]any{"trustAnchorArn": testTrustAnchorArn, "profileArn": testProfileArn, "roleArn": testRoleArn}

	t.Run("RequestARNsAreCached", func(t *testing.T) {
		fake := &fakeSessions{}
		source := rolesAnywhereSource(t, fake, &auth.RolesAnywhereConfig{})

		for range 2 {
			creds, err := retrieve(t, source, auth.Request{Values: values(t, requestARNs)})
			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, "ra-key", creds.AccessKeyID)
			assert.True(t, creds.CanExpire)
		}

		if assert.Len(t, fake.params, 1) {
			p := fake.params[0]
			assert.Equal(t, testTrustAnchorArn, p.TrustAnchorArn)
			assert.Equal(t, testProfileArn, p.ProfileArn)
			assert.Equal(t, testRoleArn, p.RoleArn)
			assert.Equal(t, int64(auth.RoleAnywhereSessionDuration), p.SessionDuration)
			assert.Equal(t, fixedNow, p.RequestTime)
		}
	})

	t.Run("ConfiguredARNsAndDuration", func(t *testing.T) {
		fake := &fakeSessions{}
		source := rolesAnywhereSource(t, fake, &auth.RolesAnywhereConfig{
			TrustAnchorArn: testTrustAnchorArn, ProfileArn: testProfileArn, RoleArn: testRoleArn,
			SessionDuration: 30 * time.Minute,
		})

		_, err := retrieve(t, source, auth.Request{})

		assert.NoError(t, err)
		assert.Equal(t, int64(1800), fake.params[0].SessionDuration)
	})

	t.Run("RotatedCertificateIsReloaded", func(t *testing.T) {
		dir := t.TempDir()
		certRef, keyRef := writeKeyPair(t, dir)
		fake := &fakeSessions{}
		source := rolesAnywhereSource(t, fake, &auth.RolesAnywhereConfig{ClientCert: certRef, PrivateKey: keyRef})

		_, err := retrieve(t, source, auth.Request{Values: values(t, requestARNs)})
		assert.NoError(t, err)

		writeKeyPair(t, dir) // rotate the files in place

		other := map[string]any{"trustAnchorArn": testTrustAnchorArn, "profileArn": testProfileArn, "roleArn": testRoleArn + "-2"}
		_, err = retrieve(t, source, auth.Request{Values: values(t, other)})
		assert.NoError(t, err)

		if assert.Len(t, fake.params, 2) {
			assert.NotEqual(t, fake.params[0].ClientCert.SerialNumber, fake.params[1].ClientCert.SerialNumber)
		}
	})

	t.Run("UnreadableCertificateAfterRotation", func(t *testing.T) {
		dir := t.TempDir()
		certRef, keyRef := writeKeyPair(t, dir)
		source := rolesAnywhereSource(t, &fakeSessions{}, &auth.RolesAnywhereConfig{ClientCert: certRef, PrivateKey: keyRef})

		assert.NoError(t, os.WriteFile(certRef.File.Path, []byte("garbage"), 0o600))

		_, err := source.Credentials(t.Context(), auth.Request{Values: values(t, requestARNs)})

		assert.ErrorIs(t, err, auth.ErrCreateRolesAnywhereSession)
		assert.ErrorIs(t, err, auth.ErrLoadCert)
	})

	t.Run("AllowList", func(t *testing.T) {
		source := rolesAnywhereSource(t, &fakeSessions{}, &auth.RolesAnywhereConfig{
			AllowedRoleArns: []string{"arn:aws:iam::123456789012:role/other"},
		})

		_, err := source.Credentials(t.Context(), auth.Request{Values: values(t, requestARNs)})

		assert.ErrorIs(t, err, auth.ErrRoleNotAllowed)
	})

	t.Run("MissingARNs", func(t *testing.T) {
		source := rolesAnywhereSource(t, &fakeSessions{}, &auth.RolesAnywhereConfig{})

		_, err := source.Credentials(t.Context(), auth.Request{Values: values(t, map[string]any{"roleArn": testRoleArn})})

		assert.ErrorIs(t, err, auth.ErrCreateRolesAnywhereSession)
	})

	t.Run("SessionError", func(t *testing.T) {
		source := rolesAnywhereSource(t, &fakeSessions{err: errTest}, &auth.RolesAnywhereConfig{})

		_, err := source.Credentials(t.Context(), auth.Request{Values: values(t, requestARNs)})

		assert.ErrorIs(t, err, auth.ErrCreateRolesAnywhereSession)
		assert.ErrorIs(t, err, errTest)
		assert.Equal(t, auth.MethodRolesAnywhere, source.Method())
	})
}
