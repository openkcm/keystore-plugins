# AWS keystore operations plugin

This plugin implements the
[Keystore Operations](https://github.com/openkcm/plugin-sdk/blob/main/proto/plugin/keystore/operations/v1/operations.proto)
service on top of AWS KMS. It is served with HashiCorp
[go-plugin](https://github.com/hashicorp/go-plugin) and configured by the host
through the `Configure` RPC, which passes the plugin's YAML configuration.

```shell
make build   # produces ./bin/keystoreop/aws
```

## Authentication

The `auth` section of the plugin configuration selects how the plugin obtains AWS
credentials. Each request still carries a keystore instance configuration; the
selected method decides which of its fields are used.

| `method`               | Credentials                                                                                              | Fields read from each request             |
|------------------------|----------------------------------------------------------------------------------------------------------|-------------------------------------------|
| `perRequest` (default) | Sent with every request: `authType` plus an access key or a Roles Anywhere certificate                   | all credentials                           |
| `ambient`              | The environment the plugin runs in (AWS SDK default chain): env vars, shared config, EKS IRSA / Pod Identity, EC2/ECS role | none                    |
| `accessKey`            | An IAM access key held in the plugin configuration                                                       | none                                      |
| `assumeRole`           | STS `AssumeRole`, starting from the ambient credentials or the access key                                | `roleArn`, `externalId`                   |
| `rolesAnywhere`        | IAM Roles Anywhere with a certificate and private key held by the plugin                                 | `trustAnchorArn`, `profileArn`, `roleArn` |

Fields sent with a request override the matching defaults in the plugin
configuration. With the plugin-held methods, any credentials a request sends are
ignored.

### Secrets

Every secret is a [source ref](https://github.com/openkcm/common-sdk/tree/main/pkg/commoncfg),
the same format used by the other OpenKCM plugins:

```yaml
# Inline value. "source: embedded" is implied when source is omitted.
value: AKIAEXAMPLE

# Environment variable
source: env
env: AWS_SECRET_ACCESS_KEY

# File, for example a mounted Kubernetes secret
source: file
file:
  path: /etc/aws/secret-access-key
```

Values are trimmed of surrounding whitespace, so files may end with a newline.

### Ambient credentials (`ambient`)

Recommended on EKS (IRSA or Pod Identity) and EC2/ECS. No secrets in the
configuration.

```yaml
auth:
  method: ambient
```

### Access key (`accessKey`)

```yaml
auth:
  method: accessKey
  accessKey:
    accessKeyId:
      source: env
      env: AWS_ACCESS_KEY_ID
    secretAccessKey:
      source: file
      file:
        path: /etc/aws/secret-access-key
    sessionToken:            # optional
      source: env
      env: AWS_SESSION_TOKEN
```

The access key is read once, when the plugin is configured.

### Assume role (`assumeRole`)

The plugin assumes a role per tenant. The role ARN, and optionally the external
ID, are sent with each request; the values below are used when a request sends
none.

```yaml
auth:
  method: assumeRole
  cacheSize: 1024                     # optional, sessions kept in memory
  assumeRole:
    source: ambient              # credentials used to call STS: ambient (default) or accessKey
    region: eu-central-1              # optional STS region; defaults to the key's region
    roleArn: arn:aws:iam::123456789012:role/openkcm-keystore
    externalId:                       # optional
      source: env
      env: AWS_EXTERNAL_ID
    sessionName: openkcm-keystore-plugin
    duration: 1h                      # 15m to 12h, default 15m
    allowedRoleArns:                  # optional allow-list, "*" matches anything
      - "arn:aws:iam::*:role/openkcm-*"
```

To start from an access key, set `source: accessKey` and add an `accessKey`
section as shown above.

Each target role must trust the plugin's identity, for example:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111111111111:role/openkcm-plugin" },
  "Action": "sts:AssumeRole",
  "Condition": { "StringEquals": { "sts:ExternalId": "tenant-external-id" } }
}
```

### IAM Roles Anywhere (`rolesAnywhere`)

The plugin holds the certificate and key; each request names the trust anchor,
profile and role of its tenant, or the defaults below apply.

```yaml
auth:
  method: rolesAnywhere
  rolesAnywhere:
    clientCert:                       # PEM, may include the intermediate chain
      source: file
      file:
        path: /etc/aws/tls.crt
    privateKey:                       # PEM RSA private key
      source: file
      file:
        path: /etc/aws/tls.key
    trustAnchorArn: arn:aws:rolesanywhere:eu-central-1:123456789012:trust-anchor/1234
    profileArn: arn:aws:rolesanywhere:eu-central-1:123456789012:profile/5678
    roleArn: arn:aws:iam::123456789012:role/openkcm-keystore
    sessionDuration: 1h               # 15m to 12h, default 1h
    allowedRoleArns:
      - "arn:aws:iam::123456789012:role/openkcm-*"
```

The certificate and key are read again whenever a new session is created, so
certificates rotated on disk (for example by cert-manager) are used without
restarting the plugin.

### Per-request credentials (`perRequest`)

Without an `auth` section, or with `method: perRequest`, the plugin behaves as
before: each request's keystore instance configuration carries the credentials provided by the host service (CMK).

```json
{ "authType": "AUTH_TYPE_SECRET", "accessKeyId": "...", "secretAccessKey": "...", "sessionToken": "..." }
```

```json
{
  "authType": "AUTH_TYPE_CERTIFICATE",
  "trustAnchorArn": "...", "profileArn": "...", "roleArn": "...",
  "clientCert": "-----BEGIN CERTIFICATE-----...", "privateKey": "-----BEGIN RSA PRIVATE KEY-----..."
}
```

### Behaviour

- **Validation:** `Configure` rejects unknown keys, unsupported methods, missing
  sections, out-of-range durations and unreadable secrets with
  `InvalidArgument`, so mistakes surface at startup.
- **Caching:** credentials are cached and refreshed 5 minutes before they expire.
  `assumeRole` keeps one session per role, external ID and STS region;
  `rolesAnywhere` one per trust anchor, profile and role. At most `cacheSize`
  sessions are kept (default 1024); the least recently used is dropped first.
- **Errors:** authentication failures return the gRPC provider authentication
  status with one of these reasons:

  | Reason                                           | Cause                                              |
  |--------------------------------------------------|----------------------------------------------------|
  | `ROLE_NOT_ALLOWED`                               | The role is not in `allowedRoleArns`               |
  | `UNTRUSTED_CERTIFICATE`, `CANNOT_ASSUME_ROLE`, `TRUST_ANCHOR_NOT_FOUND`, `ROLE_NOT_IN_PROFILE`, `PROFILE_NOT_FOUND` | Roles Anywhere rejected the session |
  | `AUTHENTICATION_ERROR`                           | Any other credentials failure, for example STS denied `AssumeRole` or no role was configured or sent |
