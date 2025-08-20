package common

type AWSConfig struct {
	AccessKeyID     string  `json:"accessKeyId"`
	SecretAccessKey string  `json:"secretAccessKey"`
	SessionToken    *string `json:"sessionToken,omitempty"`
}
