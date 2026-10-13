package rolesanywhere

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	cryptoUtils "github.com/openkcm/utils/crypto"
)

const (
	HeaderAuthorization = "Authorization"
	HeaderContentType   = "Content-Type"
	HeaderHost          = "Host"
	HeaderUserAgent     = "User-Agent"
	HeaderXAmzTraceID   = "X-Amzn-Trace-Id"
	HeaderXAmzDate      = "X-Amz-Date"
	HeaderXAmzX509      = "X-Amz-X509"
	HeaderXAmzChain     = "X-Amz-X509-Chain"

	ContentTypeApplicationJSON = "application/json"

	ServiceName = "rolesanywhere"
	SessionPath = "/sessions"
	BaseHost    = "amazonaws.com"

	SigV4Request   = "aws4_request"
	SigV4Algorithm = "AWS4-X509-RSA-SHA256"

	QueryProfileArn     = "profileArn"
	QueryRoleArn        = "roleArn"
	QueryTrustAnchorArn = "trustAnchorArn"

	TimeFormat = "20060102T150405Z"
	DateFormat = "20060102"

	ArnRegexPattern = `^arn:aws:\w+:[\w-]+:(\d){12}:.+$`
)

var (
	arnRegEx *regexp.Regexp

	ignoredHeaderKeys = map[string]struct{}{
		HeaderAuthorization: {},
		HeaderUserAgent:     {},
		HeaderXAmzTraceID:   {},
	}

	ErrInvalidAWSArn              = errors.New("invalid AWS ARN")
	ErrNoCredentialsFound         = errors.New("no credentials found")
	ErrEmptyCredentials           = errors.New("empty credentials returned")
	ErrFailedToCreateRequest      = errors.New("failed to create request")
	ErrFailedToAddRequestHeaders  = errors.New("failed to add request headers")
	ErrFailedToCreateStringToSign = errors.New("failed to create string to sign")
	ErrFailedToSignRequest        = errors.New("failed to sign request")
	ErrFailedToCreateAuthHeader   = errors.New("failed to create authorization header")
	ErrFailedToSendRequest        = errors.New("failed to send request")
	ErrReceivedAWSErrorResponse   = errors.New("received error response from AWS")
	ErrInvalidJSONResponse        = errors.New("failed to JSON decode response")
)

func init() {
	arnRegEx = regexp.MustCompile(ArnRegexPattern)
}

// Params contains the parameters required to create a session with AWS Roles Anywhere.
type Params struct {
	ProfileArn      string
	RoleArn         string
	TrustAnchorArn  string
	RequestTime     time.Time
	PrivateKey      *rsa.PrivateKey
	ClientCert      *x509.Certificate
	IntermediateCAs []*x509.Certificate
	SessionDuration int64
}

// SessionCreateRequest represents the request body for the AWS Roles Anywhere /sessions endpoint.
type SessionCreateRequest struct {
	// DurationSeconds is the specified duration (in seconds) of the session for which the token will be valid
	DurationSeconds int64 `json:"durationSeconds"`
}

// getRegionFromArn extracts the AWS region from the ARN
func getRegionFromArn(arn string) (string, error) {
	matched := arnRegEx.MatchString(arn)
	if !matched {
		return "", ErrInvalidAWSArn
	}
	// If the ARN is valid, the region is always the fourth part of the ARN
	parts := strings.Split(arn, ":")

	return parts[3], nil
}

// getHost returns the host for the AWS Roles Anywhere service
func getHost(params Params) (string, error) {
	region, err := getRegionFromArn(params.ProfileArn)
	if err != nil {
		return "", err
	}

	hostParts := []string{ServiceName, region, BaseHost}

	return strings.Join(hostParts, "."), nil
}

// GetScope returns the scope string for the AWS SigV4 signing process.
func GetScope(params Params) (string, error) {
	region, err := getRegionFromArn(params.ProfileArn)
	if err != nil {
		return "", err
	}

	scopeParts := []string{
		params.RequestTime.Format(DateFormat),
		region,
		ServiceName,
		SigV4Request,
	}

	return strings.Join(scopeParts, "/"), nil
}

// AddRequestHeaders adds the required headers to the request,
// including the client certificate, intermediate CAs, and the request time.
func AddRequestHeaders(req *http.Request, params Params) error {
	host, err := getHost(params)
	if err != nil {
		return err
	}

	req.Header.Set(HeaderHost, host)
	req.Header.Set(HeaderContentType, ContentTypeApplicationJSON)
	req.Header.Set(HeaderXAmzX509, base64.StdEncoding.EncodeToString(params.ClientCert.Raw))
	req.Header.Set(HeaderXAmzDate, params.RequestTime.Format(TimeFormat))

	b64IntermediateCAs := make([]string, 0, len(params.IntermediateCAs))
	for _, ca := range params.IntermediateCAs {
		b64IntermediateCAs = append(b64IntermediateCAs, base64.StdEncoding.EncodeToString(ca.Raw))
	}

	chainString := strings.Join(b64IntermediateCAs, ",")
	if chainString != "" {
		req.Header.Set(HeaderXAmzChain, chainString)
	}

	return nil
}

// CreateCanonicalAndSignedHeaders creates the canonical headers and signed headers.
// Ignores: authorization, user-agent, x-amzn-trace-id.
func CreateCanonicalAndSignedHeaders(req *http.Request) (string, string) {
	headerKeys := make([]string, 0, len(req.Header))

	for headerKey := range req.Header {
		if _, ignored := ignoredHeaderKeys[headerKey]; ignored {
			continue
		}

		headerKeyLower := strings.ToLower(headerKey)
		headerKeys = append(headerKeys, headerKeyLower)
	}

	// AWS expects the signed headers to be sorted alphabetically
	sort.Strings(headerKeys)

	canonicalHeaderParts := make([]string, 0, len(headerKeys))

	for _, headerKey := range headerKeys {
		headerValue := fmt.Sprintf("%s:%s\n", headerKey, req.Header.Get(headerKey))
		canonicalHeaderParts = append(canonicalHeaderParts, headerValue)
	}

	canonicalHeaders := strings.Join(canonicalHeaderParts, "")
	signedHeaders := strings.Join(headerKeys, ";")

	return canonicalHeaders, signedHeaders
}

// CreateCanonicalQueryString creates the canonical query string
// consisting of profileArn, roleArn, and trustAnchorArn (sorted alphabetically).
func CreateCanonicalQueryString(profileArn, roleArn, trustAnchorArn string) string {
	query := url.Values{
		QueryProfileArn:     {profileArn},
		QueryRoleArn:        {roleArn},
		QueryTrustAnchorArn: {trustAnchorArn},
	}

	return query.Encode()
}

// PrepareRequest creates the session create request body.
func PrepareRequest(params Params) ([]byte, error) {
	request := SessionCreateRequest{
		DurationSeconds: params.SessionDuration,
	}
	requestBytes, err := json.Marshal(request)

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}

	return requestBytes, nil
}

// CreateStringToSign creates the string to sign for the AWS SigV4 signing process.
func CreateStringToSign(
	params Params,
	canonicalQuery, canonicalHeaders, signedHeaders, hashedRequestPayload string,
) (string, error) {
	canonicalRequestParts := []string{
		http.MethodPost,
		SessionPath,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload,
	}
	canonicalRequest := strings.Join(canonicalRequestParts, "\n")
	hashedCanonicalRequest := cryptoUtils.Sha256HashHex([]byte(canonicalRequest))

	scope, err := GetScope(params)
	if err != nil {
		return "", err
	}

	stringToSignParts := []string{
		SigV4Algorithm,
		params.RequestTime.Format(TimeFormat),
		scope,
		hashedCanonicalRequest,
	}

	return strings.Join(stringToSignParts, "\n"), nil
}

// CreateAuthorizationHeader creates the authorization header for the AWS SigV4 signing process.
func CreateAuthorizationHeader(
	params Params,
	signedHeaders, signature string,
) (string, error) {
	scope, err := GetScope(params)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		SigV4Algorithm,
		params.ClientCert.SerialNumber.String(),
		scope,
		signedHeaders,
		signature,
	), nil
}

type sessionCredential struct {
	Version         string `json:"version"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      string `json:"expiration"`
}

// sessionResponse represents the response from the AWS Roles Anywhere /sessions endpoint.
// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html#response-syntax
type sessionResponse struct {
	CredentialSet []struct {
		Credentials sessionCredential `json:"credentials"`
	} `json:"credentialSet"`
	SubjectArn string `json:"subjectArn"`
}

// GetCredentials calls the /sessions endpoint to retrieve credentials from AWS Roles Anywhere.
func GetCredentials(req *http.Request) (*credentials.StaticCredentialsProvider, error) {
	client := http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToSendRequest, err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			slog.Error("failed to close response body", slog.Any("err", err))
		}
	}()

	var sessionRes sessionResponse

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: %s", ErrReceivedAWSErrorResponse, string(respBody))
	}

	if err = json.NewDecoder(resp.Body).Decode(&sessionRes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJSONResponse, err)
	}

	if len(sessionRes.CredentialSet) == 0 {
		return nil, ErrNoCredentialsFound
	}

	sessionCred := sessionRes.CredentialSet[0].Credentials
	if sessionCred.AccessKeyID == "" || sessionCred.SecretAccessKey == "" {
		return nil, ErrEmptyCredentials
	}

	credentialProvider := credentials.NewStaticCredentialsProvider(
		sessionCred.AccessKeyID,
		sessionCred.SecretAccessKey,
		sessionCred.SessionToken)

	return &credentialProvider, nil
}

// CreateSession creates a session with AWS Roles Anywhere.
// Follows the signing process described in:
// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html
func CreateSession(ctx context.Context, params Params) (*credentials.StaticCredentialsProvider, error) {
	requestURL, err := getRequestURL(params)
	if err != nil {
		return nil, err
	}
	return CreateSessionFromURL(ctx, params, requestURL)
}

func getRequestURL(params Params) (string, error) {
	host, err := getHost(params)
	if err != nil {
		return "", err
	}

	return "https://" + host + SessionPath, nil
}

// CreateSessionFromURL creates a session using an explicit URL (useful for testing).
func CreateSessionFromURL(ctx context.Context, params Params, requestURL string) (*credentials.StaticCredentialsProvider, error) {
	requestPayload, err := PrepareRequest(params)
	if err != nil {
		return nil, err
	}

	body := strings.NewReader(string(requestPayload))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, body)

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}

	if err = AddRequestHeaders(req, params); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToAddRequestHeaders, err)
	}

	canonicalQuery := CreateCanonicalQueryString(params.ProfileArn, params.RoleArn, params.TrustAnchorArn)
	canonicalHeaders, signedHeaders := CreateCanonicalAndSignedHeaders(req)
	hashedRequestPayload := cryptoUtils.Sha256HashHex(requestPayload)

	stringToSign, err := CreateStringToSign(params, canonicalQuery, canonicalHeaders, signedHeaders, hashedRequestPayload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateStringToSign, err)
	}

	signature, err := cryptoUtils.SignWithRSAPrivateKey(params.PrivateKey, []byte(stringToSign))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToSignRequest, err)
	}

	authorizationHeader, err := CreateAuthorizationHeader(params, signedHeaders, signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateAuthHeader, err)
	}

	req.URL.RawQuery = canonicalQuery
	req.Header.Set("Authorization", authorizationHeader)

	return GetCredentials(req)
}
