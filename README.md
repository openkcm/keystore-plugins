# Keystore Plugins

Default templates for SAP open source repositories, including LICENSE, .reuse/dep5, Code of Conduct, etc... All repositories on github.com/SAP will be created based on this template.

[![REUSE status](https://api.reuse.software/badge/github.com/openkcm/keystore-plugins)](https://api.reuse.software/info/github.com/openkcm/keystore-plugins)

## About this project

This repository contains plugins implementations for the Keystore Operations and Management.

The plugins need to be implemented using
Hashicorp's [go-plugin](https://github.com/hashicorp/go-plugin) library.

The plugins are used by the KMS to delegate the operations and management of the
Keystore to external systems. The
following gRPC services are defined:

- [Keystore Operations](https://github.com/openkcm/plugin-sdk/blob/main/proto/plugin/keystore/operations/v1/operations.proto)
- [Keystore Management](https://github.com/openkcm/plugin-sdk/blob/main/proto/plugin/keystore/management/v1/management.proto)

## Requirements and Setup

- To build the plugins

```shell
make build
```

- To generate the protobuf files from the proto definitions

```shell
make proto
```

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/openkcm/keystore-plugins/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Security / Disclosure
If you find any bug that may be a security problem, please follow our instructions at [in our security policy](https://github.com/openkcm/keystore-plugins/security/policy) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/openkcm/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and OpenKCM contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/openkcm/keystore-plugins).
