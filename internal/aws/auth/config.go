package auth

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
)

// Method selects how the plugin obtains AWS credentials.
type Method string

const (
	// MethodPerRequest takes authType and credentials from each request's
	// keystore instance configuration. It is the default when no method is
	// configured.
	MethodPerRequest Method = "perRequest"
	// MethodAmbient uses the credentials of the environment the plugin runs in,
	// resolved by the AWS SDK default credential chain: environment variables,
	// shared config files, EKS IRSA / Pod Identity and EC2/ECS roles.
	MethodAmbient Method = "ambient"
	// MethodAccessKey uses an IAM access key held in the plugin configuration.
	MethodAccessKey Method = "accessKey"
	// MethodAssumeRole assumes an IAM role through STS, starting from the
	// ambient credentials or the configured access key.
	MethodAssumeRole Method = "assumeRole"
	// MethodRolesAnywhere exchanges the plugin's X.509 certificate for
	// credentials through IAM Roles Anywhere.
	MethodRolesAnywhere Method = "rolesAnywhere"
)

const (
	// DefaultCacheSize is the default number of cached role sessions.
	DefaultCacheSize = 1024

	minSessionDuration = 15 * time.Minute
	maxSessionDuration = 12 * time.Hour
)

var (
	ErrInvalidAuthConfig  = errors.New("invalid AWS authentication configuration")
	ErrResolveCredentials = errors.New("failed to resolve AWS credentials")
	ErrRoleNotAllowed     = errors.New("role is not in the allowed role ARNs")

	sessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
)

// Config is the "auth" section of the plugin configuration. See the plugin
// README for examples.
type Config struct {
	Method Method `yaml:"method"`
	// CacheSize bounds the number of role sessions kept for assumeRole and
	// rolesAnywhere. The least recently used session is dropped first.
	CacheSize     int                  `yaml:"cacheSize"`
	AccessKey     *AccessKeyConfig     `yaml:"accessKey"`
	AssumeRole    *AssumeRoleConfig    `yaml:"assumeRole"`
	RolesAnywhere *RolesAnywhereConfig `yaml:"rolesAnywhere"`
}

// AccessKeyConfig holds an access key for MethodAccessKey, or the base credentials
// of MethodAssumeRole when its source is MethodAccessKey.
type AccessKeyConfig struct {
	AccessKeyID     commoncfg.SourceRef  `yaml:"accessKeyId"`
	SecretAccessKey commoncfg.SourceRef  `yaml:"secretAccessKey"`
	SessionToken    *commoncfg.SourceRef `yaml:"sessionToken"`
}

// AssumeRoleConfig configures MethodAssumeRole. A roleArn or externalId sent
// with a request overrides the values configured here.
type AssumeRoleConfig struct {
	// Source provides the credentials used to call STS: MethodAmbient
	// (the default) or MethodAccessKey.
	Source Method `yaml:"source"`
	// Region of the STS endpoint. Defaults to the region of the key.
	Region      string               `yaml:"region"`
	RoleArn     string               `yaml:"roleArn"`
	ExternalID  *commoncfg.SourceRef `yaml:"externalId"`
	SessionName string               `yaml:"sessionName"`
	// Duration of each session, between 15m and 12h. Defaults to 15m.
	Duration time.Duration `yaml:"duration"`
	// AllowedRoleArns restricts the roles that may be assumed. Each entry is
	// an ARN in which "*" matches any characters. Empty allows every role.
	AllowedRoleArns []string `yaml:"allowedRoleArns"`
}

// RolesAnywhereConfig configures MethodRolesAnywhere. The trust anchor,
// profile and role ARNs sent with a request override the values configured
// here. The certificate and key are read again for every new session, so
// rotated files are picked up without restarting the plugin.
type RolesAnywhereConfig struct {
	ClientCert     commoncfg.SourceRef `yaml:"clientCert"`
	PrivateKey     commoncfg.SourceRef `yaml:"privateKey"`
	TrustAnchorArn string              `yaml:"trustAnchorArn"`
	ProfileArn     string              `yaml:"profileArn"`
	RoleArn        string              `yaml:"roleArn"`
	// SessionDuration of each session, between 15m and 12h. Defaults to 1h.
	SessionDuration time.Duration `yaml:"sessionDuration"`
	// AllowedRoleArns restricts the roles that may be used, as for assumeRole.
	AllowedRoleArns []string `yaml:"allowedRoleArns"`
}

// DecodeConfig decodes an auth section strictly, so misspelled keys are
// reported instead of silently ignored. A nil or empty node yields the
// default MethodPerRequest configuration.
func DecodeConfig(node *yaml.Node) (Config, error) {
	var cfg Config

	if node == nil || node.Kind == 0 {
		return cfg, nil
	}

	raw, err := yaml.Marshal(node)
	if err != nil {
		return cfg, fmt.Errorf("%w: %w", ErrInvalidAuthConfig, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	err = decoder.Decode(&cfg)
	if err != nil {
		return cfg, fmt.Errorf("%w: %w", ErrInvalidAuthConfig, err)
	}

	return cfg, nil
}

// Validate checks the parts of the configuration that do not need secrets
// to be loaded.
func (c Config) Validate() error {
	if c.CacheSize < 0 {
		return invalidf("cacheSize must not be negative")
	}

	switch c.Method {
	case "", MethodPerRequest, MethodAmbient:
		return nil
	case MethodAccessKey:
		if c.AccessKey == nil {
			return invalidf("accessKey section is required")
		}

		return nil
	case MethodAssumeRole:
		return c.validateAssumeRole()
	case MethodRolesAnywhere:
		return c.validateRolesAnywhere()
	default:
		return invalidf("unsupported method %q", c.Method)
	}
}

func (c Config) validateAssumeRole() error {
	ar := c.AssumeRole
	if ar == nil {
		ar = &AssumeRoleConfig{}
	}

	switch ar.Source {
	case "", MethodAmbient:
	case MethodAccessKey:
		if c.AccessKey == nil {
			return invalidf("accessKey section is required for assumeRole source accessKey")
		}
	default:
		return invalidf("unsupported assumeRole source %q", ar.Source)
	}

	if ar.SessionName != "" && !sessionNamePattern.MatchString(ar.SessionName) {
		return invalidf("assumeRole.sessionName %q must match %s", ar.SessionName, sessionNamePattern)
	}

	err := validateDuration("assumeRole.duration", ar.Duration)
	if err != nil {
		return err
	}

	return validatePatterns("assumeRole.allowedRoleArns", ar.AllowedRoleArns)
}

func (c Config) validateRolesAnywhere() error {
	ra := c.RolesAnywhere
	if ra == nil {
		return invalidf("rolesAnywhere section is required")
	}

	err := validateDuration("rolesAnywhere.sessionDuration", ra.SessionDuration)
	if err != nil {
		return err
	}

	return validatePatterns("rolesAnywhere.allowedRoleArns", ra.AllowedRoleArns)
}

func (c Config) cacheSize() int {
	if c.CacheSize == 0 {
		return DefaultCacheSize
	}

	return c.CacheSize
}

func validateDuration(name string, d time.Duration) error {
	if d != 0 && (d < minSessionDuration || d > maxSessionDuration) {
		return invalidf("%s must be between %s and %s, got %s", name, minSessionDuration, maxSessionDuration, d)
	}

	return nil
}

func validatePatterns(name string, patterns []string) error {
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return invalidf("%s must not contain empty entries", name)
		}
	}

	return nil
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidAuthConfig, fmt.Sprintf(format, args...))
}

// loadSourceRef reads a configured value, treating an empty source as embedded.
func loadSourceRef(name string, ref commoncfg.SourceRef) (string, error) {
	if ref.Source == "" {
		ref.Source = commoncfg.EmbeddedSourceValue
	}

	value, err := commoncfg.LoadValueFromSourceRef(ref)
	if err != nil {
		return "", fmt.Errorf("%w: loading %s: %w", ErrInvalidAuthConfig, name, err)
	}

	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return "", invalidf("%s is empty", name)
	}

	return trimmed, nil
}

// loadOptionalSourceRef is like loadSourceRef but returns "" for a nil ref.
func loadOptionalSourceRef(name string, ref *commoncfg.SourceRef) (string, error) {
	if ref == nil {
		return "", nil
	}

	return loadSourceRef(name, *ref)
}
