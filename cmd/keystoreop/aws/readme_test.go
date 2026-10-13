package main_test

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v3"

	ap "github.com/openkcm/cmd/keystoreop/aws"
	awsauth "github.com/openkcm/internal/aws/auth"
)

// TestReadmeExamples keeps the configuration examples in README.md valid.
func TestReadmeExamples(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if !assert.NoError(t, err) {
		return
	}

	blocks := regexp.MustCompile("(?s)```yaml\n(auth:.*?)```").FindAllSubmatch(readme, -1)
	assert.GreaterOrEqual(t, len(blocks), 4)

	for _, block := range blocks {
		var cfg ap.PluginConfig

		if !assert.NoError(t, yaml.Unmarshal(block[1], &cfg), string(block[1])) {
			continue
		}

		authCfg, err := awsauth.DecodeConfig(&cfg.Auth)
		assert.NoError(t, err, string(block[1]))
		assert.NoError(t, authCfg.Validate(), string(block[1]))
	}
}
