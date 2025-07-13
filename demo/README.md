# SCTX Security Demo

This demo showcases SCTX (Security Context) service in both comprehensive security testing and realistic microservices architecture, demonstrating zero-trust authentication with mTLS certificates.

## Quick Start

```bash
# Run realistic microservices demo
make test-microservices

# Run comprehensive security tests
make test

# Interactive testing environment
make shell

# Run with high-performance Ed25519 (25% faster)
./sctx-demo -ed25519

# Run with FIPS-compliant ECDSA P-256 (default)
./sctx-demo
```

## Demo Modes

### 🏗️ Microservices Architecture Demo
**What it shows**: Real-world service-to-service authentication patterns
- **Order Service** (`order-service:8081`) - Manages orders, calls payment service  
- **Payment Service** (`payment-service:8082`) - Processes payments
- **SCTX Server** (`sctx-demo:8443`) - Issues and validates tokens

**Flow**: Order Service → Gets SCTX token → Calls Payment Service → Validates token

### 🔒 Security Capabilities Demo  
**What it shows**: Comprehensive security edge cases and attack prevention
- Admin bootstrap, factory patterns, rate limiting, token refresh
- 10 different security scenarios with attack/defense validation

## Architecture Overview

The demo implements a complete zero-trust security context service with:
- **mTLS authentication** - All connections require valid client certificates
- **Admin-only control** - Service configuration only through authenticated admin
- **Token-based authorization** - Short-lived context tokens with permissions
- **Pattern-based factories** - Dynamic permission assignment based on certificate attributes
- **Rate limiting** - Protection against abuse
- **Automatic token refresh** - Transparent renewal when tokens near expiry

## Security Scenarios Tested

### 1. Admin Bootstrap (One-Time)
- **Scenario**: First connection with admin certificate gets bootstrap privileges
- **Security**: Ensures only designated admin can initialize the system
- **Test**: `sctx-admin` certificate gets special permissions on first use only

### 2. Registry-Based Authentication
- **Scenario**: Pre-registered identities get specific permissions
- **Security**: Known services have explicit permission grants
- **Test**: `client-app-1` and `client-app-2` have different permission sets

### 3. Factory Pattern Matching
- **Scenario**: Certificates matching patterns get dynamic permissions
- **Security**: Flexible permission assignment without pre-registration
- **Tests**:
  - `dev.*.local` → development permissions
  - `prod.*.local` → production permissions (limited)
  - `*.team-*.local` → team collaboration permissions

### 4. Unauthorized Access Prevention
- **Scenario**: Unregistered certificates are rejected
- **Security**: Default-deny policy for unknown identities
- **Test**: `unauthorized-client` cannot get tokens

### 5. Rate Limiting
- **Scenario**: Prevent token request flooding
- **Security**: Protection against DoS and brute force
- **Test**: 6th request within a minute is rejected

### 6. Automatic Token Refresh
- **Scenario**: Tokens auto-refresh when <20% TTL remains
- **Security**: Seamless operation without long-lived tokens
- **Test**: Request after 80% TTL elapsed returns new token

### 7. Admin-Only Operations
- **Scenario**: Administrative endpoints require admin certificate
- **Security**: Separation of control plane from data plane
- **Tests**:
  - Stats, factory management require admin cert
  - Regular clients get 403 Forbidden

### 8. Factory Kill Switch
- **Scenario**: Disable compromised factories instantly
- **Security**: Emergency response capability
- **Test**: Disabled factory stops issuing tokens immediately

### 9. Token Validation
- **Scenario**: Services can verify token authenticity
- **Security**: Cryptographic proof of token validity
- **Test**: Invalid tokens are rejected

### 10. Permission-Based Access
- **Scenario**: API access based on token permissions
- **Security**: Fine-grained authorization
- **Tests**:
  - Read-only clients cannot POST
  - Write clients can GET and POST

## Certificate Structure

```
certs/
├── minica.pem              # Root CA certificate
├── minica-key.pem          # Root CA private key
├── sctx-admin/             # Admin identity (CN=sctx-admin)
├── client-app-1/           # Registered client with read/write
├── client-app-2/           # Registered client with read-only
├── dev.team-alpha.local/   # Matches dev-environment factory
├── prod.team-beta.local/   # Matches prod-environment factory
├── unauthorized-client/    # Not registered, no factory match
└── rate-limit-test/        # For testing rate limits
```

## Running the Demo

### With Docker (Recommended)
```bash
# Run all tests automatically
make test

# Start server and open interactive shell
make shell

# In the shell, test various scenarios:
curl -k --cert /certs/client-app-1/cert.pem \
     --key /certs/client-app-1/key.pem \
     https://sctx-demo:8443/context
```

### Without Docker
```bash
# Generate certificates
make certs

# Start the server
make run-local

# In another terminal, run tests
./scripts/test-scenarios.sh
```

## Manual Testing Examples

### Get a Context Token
```bash
# As registered client
curl -k --cert certs/client-app-1/cert.pem \
     --key certs/client-app-1/key.pem \
     https://localhost:8443/context

# As factory-matched client
curl -k --cert certs/dev.team-alpha.local/cert.pem \
     --key certs/dev.team-alpha.local/key.pem \
     https://localhost:8443/context
```

### Use Token for API Access
```bash
# Get token first
TOKEN=$(curl -sk --cert certs/client-app-1/cert.pem \
         --key certs/client-app-1/key.pem \
         https://localhost:8443/context | grep "Context:" | cut -d' ' -f2)

# Use token for API access
curl -k --cert certs/client-app-1/cert.pem \
     --key certs/client-app-1/key.pem \
     -H "X-Context-Token: $TOKEN" \
     https://localhost:8443/api/data
```

### Admin Operations
```bash
# View service statistics
curl -k --cert certs/sctx-admin/cert.pem \
     --key certs/sctx-admin/key.pem \
     https://localhost:8444/stats

# List factories
curl -k --cert certs/sctx-admin/cert.pem \
     --key certs/sctx-admin/key.pem \
     https://localhost:8444/factories

# Disable a factory
curl -k --cert certs/sctx-admin/cert.pem \
     --key certs/sctx-admin/key.pem \
     https://localhost:8444/disable-factory?id=dev-environment
```

## Security Model Validation

The demo validates these security principles:

1. **Zero Trust** - No implicit trust, every request authenticated
2. **Least Privilege** - Minimal permissions granted based on identity
3. **Defense in Depth** - Multiple layers (mTLS + tokens + permissions)
4. **Fail Secure** - Defaults to denial when uncertain
5. **Admin Isolation** - Control plane separated from data plane
6. **Audit Trail** - All requests logged with identity
7. **Emergency Response** - Kill switches for compromised components

## Configuration

Key configuration in `main.go`:
- `ContextTTL: 30 * time.Second` - Short TTL for demo (production: 15+ minutes)
- `RateLimitRequests: 5` - Max 5 requests per minute per identity
- `AdminIdentity: "sctx-admin"` - Expected CN for admin certificate

## Troubleshooting

### Certificate Issues
```bash
# Verify certificate CN
openssl x509 -in certs/sctx-admin/cert.pem -noout -subject

# Check certificate validity
openssl x509 -in certs/client-app-1/cert.pem -noout -dates
```

### Connection Issues
```bash
# Test basic connectivity
curl -k https://localhost:8443/health

# Debug TLS handshake
openssl s_client -connect localhost:8443 \
    -cert certs/client-app-1/cert.pem \
    -key certs/client-app-1/key.pem \
    -CAfile certs/minica.pem
```

## Production Considerations

This demo uses simplified settings for testing. In production:
- Use longer token TTLs (15+ minutes)
- Implement persistent storage for registry/tokens
- Add certificate revocation checking at edge
- Use separate CA for different trust domains
- Implement audit logging and monitoring
- Consider geographic distribution for HA