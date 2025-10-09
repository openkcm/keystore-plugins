package client_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	aws_client "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	"github.com/openkcm/keystore-plugins/internal/utils/mutator"
)

func TestAddRequestHeaders_SetsAllHeaders(t *testing.T) {
	params := aws_client.RolesAnywhereParams{
		RequestTime: time.Now().UTC(),
		ClientCert:  &x509.Certificate{Raw: []byte("client-cert")},
		ProfileArn:  "arn:aws:rolesanywhere:eu-west-2:123456789012:profile/test",
		IntermediateCAs: []*x509.Certificate{
			{Raw: []byte("intermediate-cert-1")},
			{Raw: []byte("intermediate-cert-2")},
		},
	}
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://example.com",
		nil,
	)
	err := aws_client.AddRequestHeaders(req, params)
	assert.NoError(t, err)

	assert.Equal(t, "rolesanywhere.eu-west-2.amazonaws.com", req.Header.Get("Host"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(
		t,
		base64.StdEncoding.EncodeToString(params.ClientCert.Raw),
		req.Header.Get("X-Amz-X509"),
	)
	assert.Equal(t, params.RequestTime.Format(aws_client.TimeFormat), req.Header.Get("X-Amz-Date"))

	expectedChain := strings.Join([]string{
		base64.StdEncoding.EncodeToString(params.IntermediateCAs[0].Raw),
		base64.StdEncoding.EncodeToString(params.IntermediateCAs[1].Raw),
	}, ",")
	assert.Equal(t, expectedChain, req.Header.Get("X-Amz-X509-Chain"))
}

func TestAddRequestHeaders_NoIntermediateCAs(t *testing.T) {
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://example.com",
		nil,
	)
	params := aws_client.RolesAnywhereParams{
		RequestTime: time.Now().UTC(),
		ProfileArn:  "arn:aws:rolesanywhere:eu-west-2:123456789012:profile/test",
		ClientCert:  &x509.Certificate{Raw: []byte("client-cert")},
	}

	err := aws_client.AddRequestHeaders(req, params)
	assert.NoError(t, err)

	_, ok := req.Header["X-Amz-X509-Chain"]
	assert.False(t, ok)
}

func TestCreateCanonicalAndSignedHeaders(t *testing.T) {
	headersMut := mutator.NewMutator(func() http.Header {
		return http.Header{
			"Content-Type":         []string{"application/json"},
			"X-Amz-Date":           []string{"20220101T000000Z"},
			"Host":                 []string{"example.com"},
			"X-Amz-X509":           []string{"x509-cert"},
			"X-Amz-Content-Sha256": []string{"content-sha"},
		}
	})

	tests := []struct {
		name                     string
		request                  *http.Request
		expectedCanonicalHeaders string
		expectedSignedHeaders    string
	}{
		{
			name: "TestCreateCanonicalAndSignedHeaders_ValidHeaders",
			request: &http.Request{
				Header: headersMut(),
			},
			expectedCanonicalHeaders: "content-type:application/json\n" +
				"host:example.com\n" +
				"x-amz-content-sha256:content-sha\n" +
				"x-amz-date:20220101T000000Z\n" +
				"x-amz-x509:x509-cert\n",
			expectedSignedHeaders: "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-x509",
		},
		{
			name: "TestCreateCanonicalAndSignedHeaders_EmptyHeaders",
			request: &http.Request{
				Header: http.Header{},
			},
			expectedCanonicalHeaders: "",
			expectedSignedHeaders:    "",
		},
		{
			name: "TestCreateCanonicalAndSignedHeaders_IgnoredHeaders",
			request: &http.Request{
				Header: headersMut(func(k *http.Header) {
					k.Set("Authorization", "auth token")
					k.Set("User-Agent", "go/http")
					k.Set("X-Amzn-Trace-Id", "trace-id")
				}),
			},
			expectedCanonicalHeaders: "content-type:application/json\n" +
				"host:example.com\n" +
				"x-amz-content-sha256:content-sha\n" +
				"x-amz-date:20220101T000000Z\n" +
				"x-amz-x509:x509-cert\n",
			expectedSignedHeaders: "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-x509",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalHeaders, signedHeaders := aws_client.CreateCanonicalAndSignedHeaders(tt.request)
			assert.Equal(t, tt.expectedCanonicalHeaders, canonicalHeaders)
			assert.Equal(t, tt.expectedSignedHeaders, signedHeaders)
		})
	}
}

func TestCreateCanonicalQueryString(t *testing.T) {
	profileArn := "arn:aws:rolesanywhere:eu-west-2:123456789012:profile/test"
	roleArn := "arn:aws:iam::123456789012:role/test"
	trustAnchorArn := "arn:aws:rolesanywhere:eu-west-2:123456789012:trust-anchor/test"

	expectedQueryString := "profileArn=arn%3Aaws%3Arolesanywhere%3Aeu-west-2%3A123456789012%3Aprofile%2Ftest" +
		"&roleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ftest" +
		"&trustAnchorArn=arn%3Aaws%3Arolesanywhere%3Aeu-west-2%3A123456789012%3Atrust-anchor%2Ftest"
	queryString := aws_client.CreateCanonicalQueryString(profileArn, roleArn, trustAnchorArn)

	assert.Equal(t, expectedQueryString, queryString)
}

func TestPrepareRequest(t *testing.T) {
	expectedRequest := `{"durationSeconds":3600}`

	requestBytes, err := aws_client.PrepareRequest(aws_client.RolesAnywhereParams{
		SessionDuration: 3600,
	})
	assert.NoError(t, err)
	assert.JSONEq(t, expectedRequest, string(requestBytes))
}

func TestGetScope_Valid(t *testing.T) {
	params := aws_client.RolesAnywhereParams{
		RequestTime: time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
		ProfileArn:  "arn:aws:rolesanywhere:eu-west-2:123456789012:profile/test",
	}

	scope, err := aws_client.GetScope(params)

	assert.NoError(t, err)
	assert.Equal(t, "20231001/eu-west-2/rolesanywhere/aws4_request", scope)
}

func TestGetScope_InvalidArn(t *testing.T) {
	params := aws_client.RolesAnywhereParams{
		RequestTime: time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
		ProfileArn:  "not-an-arn:eu-west-2:123456789012:profile/test",
	}

	_, err := aws_client.GetScope(params)
	assert.Error(t, err)
}

func TestCreateStringToSign(t *testing.T) {
	tests := []struct {
		name                 string
		params               aws_client.RolesAnywhereParams
		request              *http.Request
		hashedRequestPayload string
		expectedStringToSign string
	}{
		{
			name: "TestCreateStringToSign_Valid",
			params: aws_client.RolesAnywhereParams{
				ProfileArn:     "arn:aws:rolesanywhere:eu-west-2:123456789012:profile/test",
				RoleArn:        "arn:aws:iam::123456789012:role/test",
				TrustAnchorArn: "arn:aws:rolesanywhere:eu-west-2:123456789012:trust-anchor/test",
				RequestTime:    time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
				ClientCert:     &x509.Certificate{Raw: []byte("client-cert")},
				IntermediateCAs: []*x509.Certificate{
					{Raw: []byte("intermediate-cert-1")},
					{Raw: []byte("intermediate-cert-2")},
				},
			},
			request: &http.Request{
				Header: http.Header{"A": []string{"1"}, "B": []string{"2"}}},
			expectedStringToSign: "AWS4-X509-RSA-SHA256\n" +
				"20231001T120000Z\n" +
				"20231001/eu-west-2/rolesanywhere/aws4_request\n" +
				// This hash has to be correct.
				// If any input is changed, it has to be updated.
				"c686c310b81dfc06e651a53426878023ec78c2172b14840057b110639513284c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalQuery := aws_client.CreateCanonicalQueryString(tt.params.ProfileArn,
				tt.params.RoleArn, tt.params.TrustAnchorArn)
			canonicalHeaders, signedHeaders := aws_client.CreateCanonicalAndSignedHeaders(tt.request)
			stringToSign, _ := aws_client.CreateStringToSign(tt.params, canonicalQuery, canonicalHeaders,
				signedHeaders, tt.hashedRequestPayload)
			assert.Equal(t, tt.expectedStringToSign, stringToSign)
		})
	}
}

func TestCreateAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name                        string
		params                      aws_client.RolesAnywhereParams
		request                     *http.Request
		expectedAuthorizationHeader string
	}{
		{
			name: "TestCreateAuthorizationHeader_Valid",
			params: aws_client.RolesAnywhereParams{
				ProfileArn:     "arn:aws:rolesanywhere:eu-west-2:123456789012:profile/test",
				RoleArn:        "arn:aws:iam::123456789012:role/test",
				TrustAnchorArn: "arn:aws:rolesanywhere:eu-west-2:123456789012:trust-anchor/test",
				RequestTime:    time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
				ClientCert: &x509.Certificate{
					Raw:          []byte("client-cert"),
					SerialNumber: big.NewInt(1234),
				},
			},
			request: &http.Request{
				Header: http.Header{"A": []string{"1"}, "B": []string{"2"}}},
			expectedAuthorizationHeader: "AWS4-X509-RSA-SHA256 " +
				"Credential=1234/20231001/eu-west-2/rolesanywhere/aws4_request, " +
				"SignedHeaders=a;b, " +
				"Signature=some-signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, signedHeaders := aws_client.CreateCanonicalAndSignedHeaders(tt.request)
			stringToSign, _ := aws_client.CreateAuthorizationHeader(
				tt.params,
				signedHeaders,
				"some-signature",
			)
			assert.Equal(t, tt.expectedAuthorizationHeader, stringToSign)
		})
	}
}

func TestGetRolesAnywhereCredentials(t *testing.T) {
	tests := []struct {
		name                   string
		mockAWSResponse        string
		mockAWSStatusCode      int
		expectedGotCredentials bool
	}{
		{
			name:                   "TestGetRolesAnywhereCredentials_NoCreds",
			mockAWSResponse:        `{"data": "dummy"}`,
			mockAWSStatusCode:      200,
			expectedGotCredentials: false,
		},
		{
			name:                   "TestGetRolesAnywhereCredentials_ErrorResponse",
			mockAWSResponse:        `{"message": "You are doing something wrong"}`,
			mockAWSStatusCode:      400,
			expectedGotCredentials: false,
		},
		{
			name:                   "TestGetRolesAnywhereCredentials_NotJSON",
			mockAWSResponse:        "notAJSON",
			mockAWSStatusCode:      200,
			expectedGotCredentials: false,
		},
		{
			name: "TestGetRolesAnywhereCredentials_EmptyCreds",
			mockAWSResponse: `{"subjectArn": "arn:aws:rolesanywhere:eu-west-2:123456789012:subject/test", ` +
				`"credentialSet": [{"credentials": {"accessKeyId": "", "secretAccessKey": "", "sessionToken": "",` +
				`"expiration": "2024-10-11T09:58:16Z"}}]}`,
			mockAWSStatusCode:      200,
			expectedGotCredentials: false,
		},
		{
			name: "TestGetRolesAnywhereCredentials_Good",
			mockAWSResponse: `{"subjectArn": "arn:aws:rolesanywhere:eu-west-2:123456789012:subject/test", ` +
				`"credentialSet": [{"credentials": {"accessKeyId": "a", "secretAccessKey": "b", "sessionToken": "c",` +
				`"expiration": "2024-10-11T09:58:16Z"}}]}`,
			mockAWSStatusCode:      201,
			expectedGotCredentials: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAWSServer := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.mockAWSStatusCode)
					_, err := w.Write([]byte(tt.mockAWSResponse))
					assert.NoError(t, err)
				}))
			defer mockAWSServer.Close()

			mockRequest, _ := http.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				mockAWSServer.URL,
				nil,
			)
			creds, err := aws_client.GetRolesAnywhereCredentials(mockRequest)

			if tt.expectedGotCredentials {
				assert.NoError(t, err)
				assert.NotNil(t, creds)
			} else {
				assert.Error(t, err)
				assert.Nil(t, creds)
			}
		})
	}
}

func TestCreateRolesAnywhereSession(t *testing.T) {
	var (
		ProfileArn     = "arn:aws:rolesanywhere:eu-west-2:399521560603:profile/b205661b-1e50-4910-be55-0a616293bd06"
		RoleArn        = "arn:aws:iam::399521560603:role/KMSServiceRoleAnywhere"
		TrustAnchorArn = "arn:aws:rolesanywhere:eu-west-2:399521560603:trust-anchor/fe12790d-3695-4fbd-9150-64342ead324c"
	)

	clientCert := &x509.Certificate{Raw: []byte("client-cert")}
	intermediateCAs := []*x509.Certificate{
		{Raw: []byte("intermediate-cert-1")},
		{Raw: []byte("intermediate-cert-2")},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)

	ctx := context.Background()

	// Declare the parameters
	params := aws_client.RolesAnywhereParams{
		ProfileArn:      ProfileArn,
		RoleArn:         RoleArn,
		TrustAnchorArn:  TrustAnchorArn,
		RequestTime:     time.Now().UTC(),
		PrivateKey:      privateKey,
		ClientCert:      clientCert,
		IntermediateCAs: intermediateCAs,
		SessionDuration: 3600,
	}

	mockAWSResponse := `{"subjectArn": "arn:aws:rolesanywhere:eu-west-2:123456789012:subject/test", ` +
		`"credentialSet": [{"credentials": {"accessKeyId": "a", "secretAccessKey": "b", "sessionToken": "c",` +
		`"expiration": "2024-10-11T09:58:16Z"}}]}`
	mockAWSStatusCode := 201

	mockAWSServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header["Authorization"][0]
			assert.Contains(t, authHeader, "Signature")
			assert.Contains(t, authHeader, "AWS4-X509-RSA-SHA256")
			assert.Contains(
				t,
				authHeader,
				"SignedHeaders=content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain",
			)
			assert.Contains(t, authHeader, "Credential=<nil>/")
			assert.Contains(t, authHeader, "eu-west-2/rolesanywhere/aws4_request")
			assert.Equal(t, req.Header["X-Amz-X509"][0], "Y2xpZW50LWNlcnQ=")
			assert.Equal(
				t,
				req.Header["X-Amz-X509-Chain"][0],
				"aW50ZXJtZWRpYXRlLWNlcnQtMQ==,aW50ZXJtZWRpYXRlLWNlcnQtMg==",
			)
			w.WriteHeader(mockAWSStatusCode)
			_, err = w.Write([]byte(mockAWSResponse))
			assert.NoError(t, err)
		}))
	defer mockAWSServer.Close()

	// Get the credentials
	creds, err := aws_client.CreateRolesAnywhereSessionFromUrl(ctx, params, mockAWSServer.URL)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
}
