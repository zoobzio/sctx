# Contributing to SCTX

Thank you for your interest in contributing to SCTX! We welcome contributions that maintain the project's focus on security, performance, and simplicity.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/zoobzio/sctx.git
   cd sctx
   ```

2. **Install Go 1.23 or later**
   ```bash
   go version  # Should be 1.23+
   ```

3. **Install development tools**
   ```bash
   go install golang.org/x/tools/cmd/goimports@latest
   go install golang.org/x/lint/golint@latest
   go install honnef.co/go/tools/cmd/staticcheck@latest
   ```

## Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run benchmarks
cd benchmarks
go test -bench=. -benchmem

# Run security demo
cd demo
make test
```

## Code Style

- Follow standard Go conventions ([Effective Go](https://golang.org/doc/effective_go.html))
- Use `gofmt` and `goimports` for formatting
- Maintain 100% test coverage for security-critical code
- Keep the public API minimal and focused
- Document all exported functions and types

### Security Requirements

Since SCTX handles cryptographic operations and security contexts:

1. **No global state** - All state must be encapsulated in service instances
2. **Admin-only control** - Configuration changes require admin authentication
3. **Crypto best practices** - Use established algorithms (Ed25519, ECDSA P-256)
4. **Input validation** - Validate all inputs, especially certificates and tokens
5. **Error handling** - Never leak sensitive information in error messages

## Testing Guidelines

### Security Tests
All security-sensitive code must have comprehensive tests:

```go
func TestSecurityFeature(t *testing.T) {
    // Test valid cases
    t.Run("valid_input", func(t *testing.T) {
        // Test normal operation
    })
    
    // Test security boundaries
    t.Run("unauthorized_access", func(t *testing.T) {
        // Verify access is denied
    })
    
    // Test edge cases
    t.Run("malformed_input", func(t *testing.T) {
        // Verify graceful handling
    })
}
```

### Performance Tests
Use benchmarks to verify performance characteristics:

```go
func BenchmarkCryptoOperation(b *testing.B) {
    // Setup
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // Operation being benchmarked
    }
}
```

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automatic semantic versioning.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: A new feature (triggers MINOR version bump)
- **fix**: A bug fix (triggers PATCH version bump)
- **security**: A security-related change (triggers PATCH version bump)
- **perf**: Performance improvements
- **docs**: Documentation only changes
- **test**: Adding or updating tests
- **refactor**: Code changes that neither fix bugs nor add features
- **chore**: Changes to build process or auxiliary tools

### Security Changes

Security-related changes should be clearly marked:

```bash
# Security fix (patch release)
git commit -m "security: fix potential timing attack in token validation"

# Security feature (minor release)
git commit -m "feat(security): add rate limiting for authentication endpoints"

# Breaking security change (major release)
git commit -m "security!: remove deprecated insecure authentication method

BREAKING CHANGE: The deprecated BasicAuth method has been removed for security"
```

### Examples

```bash
# Patch release (0.1.0 -> 0.1.1)
git commit -m "fix: correct certificate validation edge case"

# Minor release (0.1.1 -> 0.2.0)
git commit -m "feat: add Ed25519 support for improved performance"

# Major release (0.2.0 -> 1.0.0)
git commit -m "feat!: redesign API for better security isolation

BREAKING CHANGE: Service configuration now requires admin authentication"
```

## Submitting Changes

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-security-feature`)
3. **Make your changes** following the guidelines above
4. **Add tests** for any new functionality
5. **Update documentation** as needed
6. **Commit your changes** using conventional commits
7. **Push to your branch** (`git push origin feature/amazing-security-feature`)
8. **Open a Pull Request**

## Pull Request Guidelines

### Required Checks

- [ ] All tests pass (`go test ./...`)
- [ ] Benchmarks don't regress significantly
- [ ] Security tests cover edge cases
- [ ] Documentation is updated
- [ ] No breaking changes without justification
- [ ] Code follows Go conventions

### Security Review

All security-related changes require additional review:

- Cryptographic operations must use established algorithms
- Input validation must be comprehensive
- Error messages must not leak sensitive information
- Admin operations must be properly protected

### Performance Review

Changes affecting performance need benchmark comparison:

```bash
# Before changes
go test -bench=. -benchmem > before.bench

# After changes  
go test -bench=. -benchmem > after.bench

# Compare
benchcmp before.bench after.bench
```

## Architecture Principles

When contributing, please keep these principles in mind:

### 1. Security First
- **Default Deny**: Reject unknown certificates/tokens by default
- **Least Privilege**: Grant minimal necessary permissions
- **Defense in Depth**: Multiple security layers (mTLS + tokens + permissions)
- **Admin Isolation**: Control plane separated from data plane

### 2. Performance Conscious  
- **Zero Allocations**: Minimize memory allocations in hot paths
- **Fast Crypto**: Prefer Ed25519 for performance, ECDSA P-256 for compliance
- **Efficient Lookups**: Use hash maps for O(1) registry lookups
- **Connection Reuse**: Support TLS connection pooling

### 3. Operational Simplicity
- **No Magic**: Explicit configuration over implicit behavior  
- **Observable**: Comprehensive metrics and logging
- **Testable**: Easy to test with mocked dependencies
- **Debuggable**: Clear error messages and audit trails

### 4. API Design
- **Minimal Surface**: Keep public API small and focused
- **Type Safety**: Leverage Go's type system for correctness
- **Composable**: Allow combining features in expected ways
- **Backward Compatible**: Avoid breaking changes when possible

## Common Contribution Areas

### New Features
- Additional cryptographic algorithms (after security review)
- New permission models or factory patterns
- Performance optimizations
- Operational tooling (metrics, health checks)

### Bug Fixes
- Security vulnerabilities (coordinate with maintainers)
- Performance regressions  
- Edge case handling
- Error message improvements

### Documentation
- Use case examples
- Integration guides
- Performance analysis
- Security best practices

### Testing
- Security edge cases
- Performance benchmarks
- Integration tests
- Chaos testing scenarios

## Release Process

Releases are automated based on conventional commits:

- **Patch** (0.1.0 → 0.1.1): Bug fixes, security patches
- **Minor** (0.1.1 → 0.2.0): New features, performance improvements
- **Major** (0.2.0 → 1.0.0): Breaking changes

### Security Releases

Security issues are handled with priority:

1. **Report privately** to maintainers first
2. **Coordinate disclosure** timeline
3. **Test thoroughly** before release
4. **Document impact** and mitigation steps

## Development Environment

### Recommended Setup

```bash
# Clone with all branches
git clone --recurse-submodules https://github.com/zoobzio/sctx.git

# Install pre-commit hooks
go install golang.org/x/tools/cmd/goimports@latest
git config core.hooksPath .githooks

# Set up IDE
# VS Code: Install Go extension
# GoLand: Import as Go project
# Vim: Install vim-go
```

### Testing with Real Certificates

```bash
# Generate test certificates
cd demo
make certs

# Test with real mTLS
make test-microservices
```

### Profiling Performance

```bash
# Generate CPU profile
go test -bench=BenchmarkContextGeneration -cpuprofile=cpu.prof

# View profile
go tool pprof cpu.prof
```

## Getting Help

- **Issues**: Open GitHub issues for bugs and feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Email maintainers privately for security issues
- **Chat**: [Project chat/Discord if available]

## Recognition

Contributors are recognized in:
- CHANGELOG.md for each release
- GitHub contributors page
- Special recognition for security contributions

Thank you for helping make SCTX more secure and performant!