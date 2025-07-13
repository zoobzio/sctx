# Changelog

All notable changes to SCTX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Configurable Cryptographic Algorithms**: Support for both Ed25519 (default, high-performance) and ECDSA P-256 (FIPS 140-2 compliant)
- **Algorithm Performance Benchmarks**: Comprehensive benchmarks showing Ed25519 provides ~25% better performance than ECDSA P-256
- **Crypto Abstraction Layer**: Clean abstraction allowing algorithm selection without breaking API changes
- **Enhanced Benchmarks**: Real-world performance benchmarks for public API capabilities
- **Government/Compliance Mode**: ECDSA P-256 support for FIPS 140-2 compliance requirements
- **Performance-First Defaults**: Ed25519 as default algorithm prioritizing performance over compliance

### Changed
- **Default Algorithm**: Changed from ECDSA P-256 to Ed25519 for 25% better performance
- **VerifyContext Function**: Now accepts `crypto.PublicKey` instead of `*ecdsa.PublicKey` for algorithm flexibility
- **Service Configuration**: Added `Algorithm` field to `ContextServiceConfig` for explicit algorithm selection
- **Documentation**: Updated all examples to show algorithm selection and performance trade-offs

### Performance
- **Context Verification**: 20% faster with Ed25519 (70.6μs vs 84.9μs with ECDSA P-256)
- **Full Roundtrip**: 25% faster with Ed25519 (123.4μs vs 165.4μs with ECDSA P-256)
- **Memory Usage**: No change in memory allocation patterns

### Security
- **Backward Compatibility**: Existing ECDSA P-256 deployments continue to work with explicit algorithm configuration
- **Algorithm Detection**: Automatic detection of algorithm from public key for seamless verification
- **FIPS Compliance**: ECDSA P-256 remains available for government and regulated environments

### Documentation
- **USE_CASES.md**: Comprehensive real-world use cases with complete code examples
- **CONTRIBUTING.md**: Detailed contribution guidelines with security focus
- **Algorithm Comparison**: Performance benchmarks and selection guidance
- **Enhanced README**: Improved documentation structure and examples

## [0.1.0] - Initial Release

### Added
- **Core Security Context Service**: Certificate-based authentication with signed context tokens
- **Admin-Only Control**: Point of Control architecture ensuring secure service configuration
- **Registry-Based Authentication**: Pre-configured identity to permission mappings
- **Dynamic Factory System**: Pattern-based permission assignment for flexible environments
- **Pipeline-Driven Architecture**: Pluggable processor system for authentication workflows
- **mTLS Certificate Validation**: Full X.509 certificate chain validation
- **Automatic Token Refresh**: Transparent renewal when tokens approach expiration
- **Rate Limiting**: Configurable per-identity request limiting
- **Zero-Trust Security Model**: Default deny with explicit permission grants
- **Service Discovery**: Hash-based O(1) registry lookups
- **Emergency Controls**: Factory kill switches for incident response

### Security Features
- **ECDSA P-256 Cryptography**: NIST SP 800-186 and FIPS 186-4 compliant signatures
- **Short-Lived Tokens**: Default 15-minute TTL minimizes exposure window
- **Certificate Fingerprinting**: Cryptographically bound tokens to certificates
- **Permission-Based Authorization**: Fine-grained access control
- **Admin Bootstrap Protection**: One-time admin initialization prevents takeover
- **Audit Trail**: Comprehensive logging of all security decisions

### Performance Characteristics
- **Context Generation**: ~55μs average (ECDSA P-256)
- **Context Verification**: ~88μs average (ECDSA P-256)
- **Service Discovery**: ~1.5μs average (O(1) hash lookup)
- **Permission Checking**: ~10ns average (in-memory operations)
- **Throughput**: ~18,000 authentications/second single-threaded
- **Memory**: ~7.7KB per authentication, ~3.6KB per verification

### API
- **Bootstrap**: Initialize service with admin authentication
- **RequestContext**: Issue signed context tokens for certificates
- **VerifyContext**: Validate and decode context tokens
- **RegisterIdentity**: Add service to registry with permissions
- **RegisterFactory**: Add pattern-based permission rules
- **Admin Operations**: Service stats, factory management, health checks

### Operational Features
- **In-Memory Storage**: Fast token and registry storage (production should consider persistence)
- **Concurrent Safe**: Thread-safe operations with proper locking
- **Health Monitoring**: Service health checks and operational statistics
- **Docker Support**: Complete containerized demo environment
- **Development Tools**: Certificate generation and testing utilities

### Documentation
- **Comprehensive README**: Architecture, use cases, and quick start guide
- **Interactive Demo**: 10 security scenarios with attack/defense validation
- **Benchmark Suite**: Performance analysis and optimization guidelines
- **Security Model**: Detailed threat model and security principles
- **Integration Examples**: Microservices, API gateway, and monorepo patterns

### Dependencies
- **Zero External Dependencies**: Pure Go implementation
- **Standard Library Only**: Uses only Go standard crypto packages
- **Go 1.23+**: Requires modern Go version for generics and performance

### Deployment Patterns
- **Microservices Identity Service**: Standalone authentication service
- **Embedded Security**: Library integration within applications
- **API Gateway**: Request authentication and authorization
- **Service Mesh**: Transparent service-to-service authentication
- **Development Environment**: Pattern-based dynamic permissions
- **Monorepo Security**: Package-level security boundaries

### Known Limitations
- **No Certificate Revocation**: Relies on infrastructure-level CRL/OCSP
- **In-Memory Storage**: Tokens lost on service restart (by design)
- **Single Algorithm**: ECDSA P-256 only (addressed in next release)
- **No Distributed State**: Single instance only (clustering not built-in)

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions  
- **PATCH** version for backwards-compatible bug fixes

### Security Releases

Security fixes are released immediately regardless of regular release schedule:

- **CVE fixes**: Emergency patch releases
- **Security features**: Minor releases unless breaking
- **Crypto updates**: Major releases if algorithm changes break compatibility