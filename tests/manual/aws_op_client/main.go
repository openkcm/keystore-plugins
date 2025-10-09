package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"gopkg.in/yaml.v3"

	aws "github.com/openkcm/keystore-plugins/internal/plugins/keystoreop/aws/client"
	cryptoUtils "github.com/openkcm/keystore-plugins/internal/utils/crypto"
)

var helpStr string = `Arguments: <ARN yaml path> <Cert path> <PKey path>.
See account-creation-end-to-end.md for more details`

var debug bool = false

//nolint:tagliatelle
type ConfiguredArns struct {
	ProfileArn     string `json:"profile_arn"`
	RoleArn        string `json:"role_arn"`
	TrustAnchorArn string `json:"trust_anchor_arn"`
}

func errCheck(err error) {
	if err != nil {
		panic(fmt.Sprintf("\n\nError: %v", err))
	}
}

func main() {
	if len(os.Args) != 4 { //nolint:mnd
		panic(helpStr)
	}

	if debug {
		l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		slog.SetDefault(l) // configures log package to print with LevelInfo
	}

	var (
		arnPath  = os.Args[1]
		certPath = os.Args[2]
		keyPath  = os.Args[3]
	)

	arnyaml, err := os.ReadFile(arnPath)
	errCheck(err)

	var arns ConfiguredArns

	err = yaml.Unmarshal(arnyaml, &arns)
	fmt.Printf("%s%v", arnPath, arns) //nolint:forbidigo
	errCheck(err)

	// Load client cert and intermediate CAs
	certBytes, err := os.ReadFile(certPath)
	errCheck(err)
	clientCert, intermediateCAs, err := cryptoUtils.LoadCertificates(certBytes)
	errCheck(err)

	// Load private key
	privateKeyBytes, err := os.ReadFile(keyPath)
	errCheck(err)
	privateKey, err := cryptoUtils.LoadRSAPrivateKey(privateKeyBytes)
	errCheck(err)

	ctx := context.Background()

	// Declare the parameters
	params := aws.RolesAnywhereParams{
		ProfileArn:      arns.ProfileArn,
		RoleArn:         arns.RoleArn,
		TrustAnchorArn:  arns.TrustAnchorArn,
		RequestTime:     time.Now().UTC(),
		PrivateKey:      privateKey,
		ClientCert:      clientCert,
		IntermediateCAs: intermediateCAs,
		SessionDuration: 3600, //nolint:mnd
	}

	// Get the credentials
	credentials, err := aws.CreateRolesAnywhereSession(ctx, params)
	errCheck(err)
	fmt.Println("\nSuccessfully created operations client") //nolint:forbidigo

	// Create a client with the credentials
	client := aws.NewClientWithOptions(ctx, "us-east-1", credentials)
	exportedClient := client.ExportInternalClient()

	// List the keys
	keys, err := exportedClient.ListKeys(ctx, &kms.ListKeysInput{})
	errCheck(err)
	fmt.Printf("\nSuccessfully listed keys: %v\n", keys.Keys) //nolint:forbidigo
}
