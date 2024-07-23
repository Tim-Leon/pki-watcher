# PKI Watcher

**Warning**: This library is in an early stage and might have multiple issues. Use with caution.

## Overview

PKI Watcher is a library designed to retrieve and monitor Public Key Infrastructure (PKI) data from various sources, such as Kubernetes, files, or SPIFFE. It supports gracefully reloading PKI using streams, ensuring your application remains secure and up-to-date.

## Features

- **Source Support**: Retrieve PKI data from multiple sources:
    - Kubernetes
    - Files 🚧
    - SPIFFE 🚧
- **Graceful Reloading**: Seamlessly reload PKI data using streams.
- **PKI Data Parsing**: Parse PKI data in PEM format with DER encoding, supporting the following formats:
    - PKCS#1
    - PKCS#2
    - PKCS#3
    - PKCS#8
- **Identity Creation**: Automatically parse PKI data to create identities that include:
    - Certificate
    - Corresponding private key (RSA or EC)
    - Server name (DNS or IP address)
    - Intermediate certificate
    - CA certificate

## Usage

### Example

Here’s a quick example of how to use PKI Watcher:

```rust
// Example code snippet showing how to use the PKI Watcher library
```

### Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
pki-watcher = "0.1.0"
```

### API

#### Retrieving PKI Data

```rust
// Example code snippet for retrieving PKI data from various sources
```

#### Parsing PKI Data

```rust
// Example code snippet for parsing PKI data and creating identities
```

## Future Enhancements

We have several features planned for future releases:

- **OCSP Support**: Implementing Online Certificate Status Protocol (OCSP) for checking certificate revocation status.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss the changes you’d like to make.

## Contact

For any questions or issues, please open an issue on GitHub.
