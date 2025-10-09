package client

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

	cryptoUtils "github.com/openkcm/keystore-plugins/internal/utils/crypto"
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

	RolesAnywhereName        = "rolesanywhere"
	RolesAnywhereSessionPath = "/sessions"
	RolesAnywhereBaseHost    = "amazonaws.com"

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

// RolesAnywhereParams contains the parameters required to create a session with AWS Roles Anywhere
type RolesAnywhereParams struct {
	ProfileArn      string
	RoleArn         string
	TrustAnchorArn  string
	RequestTime     time.Time
	PrivateKey      *rsa.PrivateKey
	ClientCert      *x509.Certificate
	IntermediateCAs []*x509.Certificate
	SessionDuration int64
}

// SessionCreateRequest represents the request body for the AWS Roles Anywhere /sessions endpoint
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
func getHost(params RolesAnywhereParams) (string, error) {
	region, err := getRegionFromArn(params.ProfileArn)
	if err != nil {
		return "", err
	}

	hostParts := []string{RolesAnywhereName, region, RolesAnywhereBaseHost}

	return strings.Join(hostParts, "."), nil
}

// getScope returns the scope string for the AWS SigV4 signing process
func getScope(params RolesAnywhereParams) (string, error) {
	region, err := getRegionFromArn(params.ProfileArn)
	if err != nil {
		return "", err
	}

	scopeParts := []string{
		params.RequestTime.Format(DateFormat),
		region,
		RolesAnywhereName,
		SigV4Request,
	}

	return strings.Join(scopeParts, "/"), nil
}

// addRequestHeaders adds the required headers to the request
// including the client certificate, intermediate CAs, and the request time.
func addRequestHeaders(req *http.Request, params RolesAnywhereParams) error {
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

// createCanonicalAndSignHeaders creates the canonical headers and signed headers
// this will ignore the headers: authorization, user-agent, x-amzn-trace-id
func createCanonicalAndSignedHeaders(req *http.Request) (string, string) {
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

// createCanonicalQueryString creates the canonical query string
// consisting of the profileArn, roleArn, and trustAnchorArn.
// The query string must be sorted alphabetically.
func createCanonicalQueryString(profileArn, roleArn, trustAnchorArn string) string {
	query := url.Values{
		QueryProfileArn:     {profileArn},
		QueryRoleArn:        {roleArn},
		QueryTrustAnchorArn: {trustAnchorArn},
	}

	return query.Encode()
}

// prepareRequest creates the session create request
func prepareRequest(params RolesAnywhereParams) ([]byte, error) {
	request := SessionCreateRequest{
		DurationSeconds: params.SessionDuration,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}

	return requestBytes, nil
}

// createStringToSign creates the string to sign for the AWS SigV4 signing process
func createStringToSign(
	params RolesAnywhereParams,
	canonicalQuery, canonicalHeaders, signedHeaders, hashedRequestPayload string,
) (string, error) {
	canonicalRequestParts := []string{
		http.MethodPost,
		RolesAnywhereSessionPath,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload,
	}
	canonicalRequest := strings.Join(canonicalRequestParts, "\n")
	hashedCanonicalRequest := cryptoUtils.Sha256HashHex([]byte(canonicalRequest))

	scope, err := getScope(params)
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

// createAuthorizationHeader creates the authorization header for the AWS SigV4 signing process
func createAuthorizationHeader(
	params RolesAnywhereParams,
	signedHeaders, signature string,
) (string, error) {
	scope, err := getScope(params)
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

// sessionResponse represents the response from the AWS Roles Anywhere /sessions endpoint
// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html#response-syntax
type sessionResponse struct {
	CredentialSet []struct {
		Credentials sessionCredential `json:"credentials"`
	} `json:"credentialSet"`
	SubjectArn string `json:"subjectArn"`
}

// getRolesAnywhereCredentials calls the /sessions endpoint to retrieve credentials from AWS Roles Anywhere
func getRolesAnywhereCredentials(
	req *http.Request,
) (*credentials.StaticCredentialsProvider, error) {
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

// CreateRolesAnywhereSession creates a request to create a session with AWS Roles Anywhere
// Follows Signing process described in
// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html
func CreateRolesAnywhereSession(ctx context.Context, params RolesAnywhereParams) (
	*credentials.StaticCredentialsProvider, error) {
	requestURL, err := getRolesAnywhereRequestUrl(params)
	if err != nil {
		return nil, err
	}

	return createRolesAnywhereSessionFromUrl(ctx, params, requestURL)
}

func getRolesAnywhereRequestUrl(params RolesAnywhereParams) (string, error) {
	host, err := getHost(params)
	if err != nil {
		return "", err
	}

	return "https://" + host + RolesAnywhereSessionPath, nil
}

func createRolesAnywhereSessionFromUrl(ctx context.Context, params RolesAnywhereParams,
	requestURL string) (*credentials.StaticCredentialsProvider, error) {
	requestPayload, err := prepareRequest(params)
	if err != nil {
		return nil, err
	}

	body := strings.NewReader(string(requestPayload))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}

	if err = addRequestHeaders(req, params); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToAddRequestHeaders, err)
	}

	canonicalQuery := createCanonicalQueryString(params.ProfileArn, params.RoleArn,
		params.TrustAnchorArn)
	canonicalHeaders, signedHeaders := createCanonicalAndSignedHeaders(req)
	hashedRequestPayload := cryptoUtils.Sha256HashHex(requestPayload)

	stringToSign, err := createStringToSign(params, canonicalQuery, canonicalHeaders,
		signedHeaders, hashedRequestPayload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateStringToSign, err)
	}

	signature, err := cryptoUtils.SignWithRSAPrivateKey(params.PrivateKey, []byte(stringToSign))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToSignRequest, err)
	}

	authorizationHeader, err := createAuthorizationHeader(params, signedHeaders, signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreateAuthHeader, err)
	}

	req.URL.RawQuery = canonicalQuery
	req.Header.Set("Authorization", authorizationHeader)

	return getRolesAnywhereCredentials(req)
}
