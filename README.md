# SCTX - Security Context Service

Build secure, zero-trust microservices with certificate-based authentication and cryptographically signed context tokens.

SCTX provides a lightweight, high-performance security context service that issues tamper-proof tokens based on mTLS client certificate authentication. No dependencies, no global state, just clean security primitives.

```go
// Bootstrap the service with admin authentication
admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
    CAPool:        caPool,
    PrivateKey:    privateKey,
    Algorithm:     sctx.CryptoEd25519, // High performance (default)
    Registry:      registry,
    AdminIdentity: "admin-service",
    ContextTTL:    15 * time.Minute,
})

// Services request context tokens with mTLS certificates
service := admin.GetService()
token, err := service.RequestContext(clientCert)

// Other services verify tokens cryptographically  
contextData, err := sctx.VerifyContext(token.Context(), admin.GetPublicKey())
if contextData.HasPermission("orders:write") {
    // Process authorized request
}
```

## Why SCTX?

### The Problem: Scattered Authentication Logic

Every microservices architecture eventually looks like this:

```go
// Repeated in every service handler 😫
func handleOrderRequest(w http.ResponseWriter, r *http.Request) {
    // Certificate validation scattered everywhere
    clientCert := extractCertFromTLS(r)
    if clientCert == nil {
        http.Error(w, "No certificate", 401)
        return
    }
    
    // Service identity logic duplicated
    serviceName := clientCert.Subject.CommonName
    if !isKnownService(serviceName) {
        http.Error(w, "Unknown service", 403)
        return
    }
    
    // Permission checking copy-pasted
    if !hasPermission(serviceName, "orders:write") {
        http.Error(w, "Insufficient permissions", 403)
        return
    }
    
    // Rate limiting logic scattered
    if isRateLimited(serviceName) {
        http.Error(w, "Rate limited", 429)
        return
    }
    
    // Finally... actual business logic
    processOrder(r)
}
// Copy-pasted across every microservice 😢
```

### The Solution: Centralized Security Context

```go
// Create a security context service
admin, _ := sctx.Bootstrap(config)
service := admin.GetService()

// Clean service handlers
func handleOrderRequest(w http.ResponseWriter, r *http.Request) {
    // Get authenticated context token
    token, err := service.RequestContext(extractCertFromTLS(r))
    if err != nil {
        http.Error(w, "Authentication failed", 401)
        return
    }
    
    // Verify token and permissions
    context, err := sctx.VerifyContext(token.Context(), publicKey)
    if err != nil || !context.HasPermission("orders:write") {
        http.Error(w, "Unauthorized", 403)
        return
    }
    
    // Clean business logic with authenticated context
    processOrder(r, context)
}
```

**Result**: No more scattered authentication. No more copy-paste security logic. Just clean, centralized, cryptographically secure authentication.

### The Problem: Certificate Trust Confusion

Service-to-service authentication gets tangled with manual certificate validation:

```go
// Impossible to audit or manage 😫
func callPaymentService(orderID string) error {
    // Manual certificate validation in every client
    cert := loadServiceCert("payment-service")
    if cert == nil || cert.Subject.CommonName != "payment-service" {
        return errors.New("invalid payment service cert")
    }
    
    // Trust decisions scattered across codebase
    if !isTrustedService("payment-service") {
        return errors.New("untrusted service")
    }
    
    // No audit trail of service interactions
    conn, err := tls.Dial("tcp", "payment-service:8443", &tls.Config{
        Certificates: []tls.Certificate{cert},
    })
    
    // Business logic mixed with authentication
    return processPayment(conn, orderID)
}
```

### The Solution: Cryptographic Service Identity

```go
// Centralized trust and auditable service calls
func callPaymentService(orderID string) error {
    // Get cryptographically signed service token
    token, err := sctxService.RequestContext(myCert)
    if err != nil {
        return fmt.Errorf("service authentication failed: %w", err)
    }
    
    // Make authenticated call with verifiable context
    req := PaymentRequest{
        OrderID: orderID,
        Context: string(token.Context()), // Tamper-proof identity
    }
    
    // Payment service can cryptographically verify the caller
    return sendPaymentRequest(req)
}

// In payment service: clean verification
func processPayment(req PaymentRequest) error {
    context, err := sctx.VerifyContext(sctx.Context(req.Context), publicKey)
    if err != nil {
        return fmt.Errorf("invalid service context: %w", err)
    }
    
    // Verify caller has payment permissions
    if !context.HasPermission("payments:process") {
        return fmt.Errorf("service %s lacks payment permissions", context.ID)
    }
    
    // Audit trail: we know exactly who made this call
    auditLog.Record(context.ID, "payment_processed", req.OrderID)
    
    // Process with verified service identity
    return processPaymentWithProvider(req.OrderID)
}
```

**Result**: Cryptographic service identity. Auditable service interactions. No more manual certificate validation!

### The Problem: Development vs Production Security Gap

Development environments have weak security, production has complex setup:

```go
// Development: No security (dangerous) 😱
if os.Getenv("ENV") == "development" {
    // Skip all authentication in dev
    return processRequest(req)
}

// Production: Complex certificate management 😫
cert, err := loadCertFromSecretManager(serviceName)
if err != nil {
    // Complex error handling for cert loading
}

// Different code paths = security bugs
if env == "production" {
    return authenticatedProcess(req, cert)
} else {
    return processRequest(req) // Oops! Security bypass in staging
}
```

### The Solution: Consistent Security Across Environments

```go
// Same security code across all environments
admin, _ := sctx.Bootstrap(sctx.ContextServiceConfig{
    CAPool:        loadCAForEnvironment(), // Different CAs per env
    Algorithm:     sctx.CryptoEd25519,     // Same fast crypto
    Registry:      createRegistry(),        // Environment-specific permissions
    AdminIdentity: "admin",
    ContextTTL:    getTTLForEnvironment(), // Shorter in dev for testing
})

// Development gets dynamic permissions via factories
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "dev-services",
    MatchPattern: `^dev\.(.+)\.local$`,
    Permissions:  []string{"api:read", "api:write", "debug:enable"},
})

// Production gets explicit registry entries
registry.Register("order-service", sctx.RegistryEntry{
    Type:        "service",
    Permissions: []string{"orders:read", "orders:write"},
})

// Identical authentication logic across environments
func handleRequest(w http.ResponseWriter, r *http.Request) {
    token, err := service.RequestContext(extractCert(r))
    if err != nil {
        http.Error(w, "Authentication failed", 401)
        return
    }
    // Same code path, different permissions per environment
    processAuthenticatedRequest(r, token)
}
```

**Result**: Consistent security model. No environment-specific bypasses. Strong security in development!

## Installation

```bash
go get github.com/zoobzio/sctx
```

## Quick Start

### 1. Choose Your Cryptographic Algorithm

```go
// High-performance (default) - 25% faster verification
config := sctx.ContextServiceConfig{
    Algorithm: sctx.CryptoEd25519, // or omit for default
    // ...
}

// FIPS 140-2 compliant - required for government/regulated industries
config := sctx.ContextServiceConfig{
    Algorithm: sctx.CryptoECDSAP256,
    // ...
}
```

### 2. Bootstrap the Service

```go
// Create registry with service permissions
registry := sctx.NewMemoryRegistry()
registry.Register("order-service", sctx.RegistryEntry{
    Type:        "service",
    Permissions: []string{"orders:read", "orders:write", "payments:request"},
})

registry.Register("payment-service", sctx.RegistryEntry{
    Type:        "service",
    Permissions: []string{"payments:process", "audit:write"},
})

// Bootstrap with admin authentication
admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
    CAPool:        caPool,          // Your CA certificate pool
    PrivateKey:    privateKey,      // Service private key
    Algorithm:     sctx.CryptoEd25519, // Performance-optimized default
    Registry:      registry,
    AdminIdentity: "admin-service", // Expected admin certificate CN
    ContextTTL:    15 * time.Minute,
}, map[string]interface{}{
    "deployment": "production",
})
```

### 3. Configure Service Pipeline

```go
// Configure authentication pipeline with composable processors
ops := admin.GetOperations()
processor := sctx.NewSecurityProcessor[map[string]interface{}](ops)

// Get active factories for dynamic authorization
factories, _ := admin.ListFactories()

admin.Register(
    processor.CertificateValidator(),     // Validate mTLS certificates
    processor.RegistryLookup(),           // Check pre-registered services
    processor.FactoryMatcher(factories),  // Dynamic pattern-based auth
    processor.DefaultDeny(),              // Deny unknown services (fail-secure)
)

// Complete bootstrap - locks admin identity
admin.CompleteBootstrap()
service := admin.GetService()
```

### 4. Issue Context Tokens

```go
// Service requests authentication
func authenticateService(clientCert *x509.Certificate) (*sctx.Token, error) {
    token, err := service.RequestContext(clientCert)
    if err != nil {
        return nil, fmt.Errorf("authentication failed: %w", err)
    }
    return token, nil
}
```

### 5. Verify Context Tokens

```go
// Verify tokens in downstream services
func verifyServiceRequest(contextToken string) (*sctx.ContextData, error) {
    publicKey := admin.GetPublicKey() // Get from admin or service discovery
    
    contextData, err := sctx.VerifyContext(sctx.Context(contextToken), publicKey)
    if err != nil {
        return nil, fmt.Errorf("invalid context: %w", err)
    }
    
    return contextData, nil
}

// Check permissions
func requirePermission(contextData *sctx.ContextData, permission string) error {
    if !contextData.HasPermission(permission) {
        return fmt.Errorf("service %s lacks permission %s", contextData.ID, permission)
    }
    return nil
}
```

### 6. Add Dynamic Permissions (Optional)

```go
// Factory for development environments
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "dev-services",
    MatchField:   "CN",
    MatchPattern: `^dev\.(.+)\.local$`,
    Permissions:  []string{"api:read", "api:write", "debug:enable"},
    TTLOverride:  30 * time.Minute, // Longer for dev productivity
})

// Factory for CI/CD pipelines
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "ci-pipelines",
    MatchField:   "CN", 
    MatchPattern: `^ci\.(.+)\.build$`,
    Permissions:  []string{"deploy:staging", "tests:run"},
    TTLOverride:  5 * time.Minute, // Short for security
})
```

## Core Concepts

### Point of Control (Security Feature)
SCTX enforces a strict **admin-only configuration** model where all service configuration and management flows through an authenticated admin service. This critical security feature ensures:

```go
// ❌ NO PUBLIC CONFIGURATION METHODS - This is intentional!
// service.AddPermission("orders:write")  // Does not exist
// service.RegisterIdentity(...)           // Does not exist
// service.UpdateFactory(...)              // Does not exist

// ✅ ALL CONFIGURATION REQUIRES ADMIN AUTHENTICATION
admin, _ := sctx.Bootstrap(config)  // Admin must authenticate first
admin.RegisterIdentity(...)          // Only admin can register
admin.RegisterFactory(...)           // Only admin can add factories
admin.DisableFactory(...)            // Only admin can disable

// After bootstrap completion, configuration is locked
admin.CompleteBootstrap()
service := admin.GetService()  // Service can only authenticate, not configure
```

**Why This Matters**:
- **Lateral Movement Prevention**: Compromised services cannot grant themselves additional permissions
- **Configuration Integrity**: Security policies cannot be modified by application code
- **Audit Trail**: All configuration changes flow through a single authenticated control point
- **Separation of Concerns**: Clear boundary between service operation and security configuration
- **Defense in Depth**: Even with code execution, attackers cannot modify security policies

This is not a limitation - it's a fundamental security architecture decision that prevents entire classes of attacks.

### Security Context Tokens
Clients present X.509 certificates via mTLS and receive cryptographically signed tokens containing:
- **Identity**: Extracted from certificate CN/SAN fields
- **Permissions**: Based on registry entries or factory pattern matches
- **Cryptographic Signature**: Ed25519 (default) or ECDSA P-256 (FIPS) for tamper-proof verification
- **Short TTL**: Default 15-minute expiration with automatic refresh
- **Certificate Binding**: Cryptographically bound to the presenting certificate

### Configurable Cryptography
SCTX supports two cryptographic algorithms optimized for different use cases:

**Ed25519 (Default - High Performance)**
```go
config := sctx.ContextServiceConfig{
    Algorithm: sctx.CryptoEd25519, // or omit for default
    // 25% faster verification than ECDSA P-256
    // Perfect for high-throughput APIs and edge computing
}
```

**ECDSA P-256 (FIPS 140-2 Compliant)**
```go
config := sctx.ContextServiceConfig{
    Algorithm: sctx.CryptoECDSAP256,
    // Required for government and regulated industries
    // NIST SP 800-186 and FIPS 186-4 compliant
}
```

## Architecture Patterns

### Microservices Identity Service
The primary deployment pattern positions SCTX as a standalone identity service:

```
┌─────────────────┐     mTLS      ┌─────────────────┐
│   Service A     │──────────────▶│                 │
│ (certificate)   │               │      SCTX       │
└─────────────────┘               │ Identity Service│
                                  │                 │
┌─────────────────┐     mTLS      │                 │
│   Service B     │──────────────▶│                 │
│ (certificate)   │◀──────────────│                 │
└─────────────────┘  Context Token└─────────────────┘
```

Services authenticate to SCTX with certificates and receive context tokens for inter-service communication.

### Service-to-Service Authentication
The most common pattern for microservices authentication:

```go
// 1. Order Service gets its own SCTX token
orderServiceCert := tls.LoadX509KeyPair("order-service.crt", "order-service.key")
orderToken, err := sctxService.RequestContext(orderServiceCert)

// 2. Order Service calls Payment Service with its token
req, _ := http.NewRequest("POST", "https://payment-service/process", body)
req.Header.Set("X-Context-Token", orderToken.Context())
resp, err := client.Do(req)

// 3. Payment Service verifies the caller's identity and permissions
func (p *PaymentService) ProcessPayment(r *http.Request) {
    token := r.Header.Get("X-Context-Token")
    context, err := sctx.VerifyContext(sctx.Context(token), publicKey)
    if err != nil {
        return errors.New("invalid service credentials")
    }
    
    // Check if caller has permission to process payments
    if !context.HasPermission("payments:process") {
        return errors.New("service lacks payment permissions")
    }
    
    log.Printf("Processing payment for service: %s", context.ID)
    // ... process payment
}
```

### Processor Pipeline Marketplace
SCTX features a powerful plugin architecture for authentication processors. Create custom processors, use built-in defaults, or leverage community-developed processors:

```go
// Built-in processors for common security needs
processor := sctx.NewSecurityProcessor[map[string]interface{}](ops)

admin.Register(
    processor.CertificateValidator(),     // Certificate validation
    processor.RateLimiter(limiter),       // Request rate limiting
    processor.AuditLogger(logger),        // Security audit trail
    processor.ThreatDetector(),           // Anomaly detection
)

// Create your own custom processor
func GeoLocationProcessor() PipelineProcessor[map[string]interface{}] {
    return func(req *ContextRequest[map[string]interface{}]) (*ContextRequest[map[string]interface{}], error) {
        // Add geolocation data to context metadata
        if req.Metadata == nil {
            req.Metadata = make(map[string]interface{})
        }
        req.Metadata["geo_country"] = detectCountry(req.RemoteAddr)
        req.Metadata["geo_risk_score"] = calculateGeoRisk(req.RemoteAddr)
        
        // Deny high-risk locations
        if req.Metadata["geo_risk_score"].(int) > 80 {
            req.Allowed = false
            req.DenialReason = "high-risk geolocation"
        }
        return req, nil
    }
}

// Community processors (future ecosystem)
// import "github.com/acme/sctx-processors/compliance"
// admin.Register(compliance.SOC2Processor())
// admin.Register(compliance.HIPAAProcessor())
```

The processor marketplace enables:
- **Extensibility**: Add custom authentication logic without forking
- **Reusability**: Share processors across projects and teams
- **Compliance**: Pre-built processors for regulatory requirements
- **Innovation**: Community-driven security enhancements

### Factory vs Registry: Multi-Tenancy Patterns

**Registry**: Pre-configured services with explicit permissions
```go
// Perfect for production with known services
registry.Register("payment-service", sctx.RegistryEntry{
    Type:        "service",
    Permissions: []string{"payments:process", "refunds:issue"},
})

registry.Register("user-service", sctx.RegistryEntry{
    Type:        "service",
    Permissions: []string{"users:read", "users:write"},
})
```

**Factories**: Dynamic pattern-based authorization for multi-tenancy
```go
// Multi-tenant SaaS with per-tenant isolation
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "tenant-services",
    MatchField:   "CN",
    MatchPattern: `^([a-z0-9-]+)\.([a-z0-9-]+)\.tenant\.local$`, // tenant-id.service-name.tenant.local
    Permissions:  []string{"api:read", "api:write"},
    // Extracted groups: $1 = tenant-id, $2 = service-name
})

// Customer-specific environments
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "customer-instances",
    MatchField:   "CN",
    MatchPattern: `^(.+)\.customer-([a-f0-9]{8})\.cloud$`, // service.customer-uuid.cloud
    Permissions:  []string{"customer:$2:access"}, // Dynamic permission per customer
    TTLOverride:  2 * time.Hour,
})

// Development teams with namespace isolation
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "dev-teams",
    MatchField:   "CN",
    MatchPattern: `^dev\.team-([a-z]+)\.(.+)$`, // dev.team-alpha.service
    Permissions:  []string{"dev:team:$1", "namespace:$1:full"},
})
```

Factories enable zero-trust multi-tenancy where:
- **Users/Tenants**: Isolated by certificate patterns
- **Dynamic Provisioning**: New tenants without registry updates
- **Namespace Isolation**: Teams can't access other team resources
- **Customer Segregation**: Complete data isolation per customer

### Flexible Permission Model
SCTX doesn't enforce any permission naming convention - you define what makes sense for your architecture:

```go
// REST API style
Permissions: []string{"GET:/api/orders", "POST:/api/orders", "DELETE:/api/orders/*"}

// Resource:Action style
Permissions: []string{"orders:read", "orders:write", "orders:delete"}

// Hierarchical style
Permissions: []string{"api.orders.read", "api.orders.write", "api.payments.process"}

// Role-based style
Permissions: []string{"role:admin", "role:operator", "scope:production"}

// Custom domain-specific
Permissions: []string{"trade:execute", "position:view", "risk:override:level2"}

// Verify permissions your way
if context.HasPermission("trade:execute") && context.HasPermission("risk:override:level2") {
    // Execute high-risk trade
}
```

### Monorepo Security Barriers
A novel use case enables security boundaries within a single application:

```go
// Package A requests context with its certificate
tokenA := sctxClient.RequestContext(certA)

// Package B validates token before accepting transaction
if err := sctxClient.ValidateContext(tokenA); err != nil {
    return ErrUnauthorized
}
```

This pattern creates auditable, identity-based transactions between packages in a monorepo.

## Quick Start

```go
import "github.com/zoobzio/sctx"

// Bootstrap the service (one-time, admin only)
admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
    CAPool:        caPool,
    PrivateKey:    privateKey,
    Registry:      registry,
    AdminIdentity: "admin-service",
    ContextTTL:    15 * time.Minute,
})

// Register known service identities
admin.RegisterIdentity("payment-service", sctx.RegistryEntry{
    Type:        "service",
    Permissions: []string{"orders:read", "payments:process"},
})

// Or use factories for pattern-based registration
admin.RegisterFactory(&sctx.ContextFactory{
    ID:           "dev-services",
    MatchField:   "CN",
    MatchPattern: `^dev\.(.+)\.local$`,
    Permissions:  []string{"dev:debug"},
})

// Client services request contexts
service := admin.GetService()
token, err := service.RequestContext(tlsConnectionState)

// Other services verify tokens
data, err := sctx.VerifyContext(token.Context(), publicKey)
```

## Performance

SCTX is designed for high-performance production environments with minimal overhead:

### Algorithm Performance Comparison (AMD Ryzen 5 3600X)

**Ed25519 (Default - Recommended)**
- Context Verification: **70.6μs** average
- Full Roundtrip (generate + verify): **123.4μs** average
- Throughput: **~14,000 verifications/second**

**ECDSA P-256 (FIPS Compliant)**
- Context Verification: **84.9μs** average  
- Full Roundtrip (generate + verify): **165.4μs** average
- Throughput: **~11,800 verifications/second**

**Performance Summary:**
- Ed25519 provides **25% better performance** than ECDSA P-256
- Context generation is identical (~51μs) due to pipeline overhead
- Memory usage is identical (~7.7KB per auth, ~3.6KB per verification)

### Real-World Performance
- **Single-threaded**: ~18,000 authentications/second
- **Multi-threaded**: Scales linearly with excellent concurrent performance
- **Service Discovery**: ~1.5μs (O(1) hash lookup, scales to 1000+ services)
- **Permission Checking**: ~10ns (zero allocations after authentication)

See [benchmarks/](benchmarks/) for detailed performance analysis and optimization guidelines.

## Features

### Cryptographic Algorithms
- **Ed25519**: Default high-performance algorithm (25% faster verification)
- **ECDSA P-256**: FIPS 140-2 compliant for government/regulated industries
- **Algorithm Detection**: Automatic detection from public keys for seamless verification
- **Configurable**: Choose algorithm per deployment based on performance vs. compliance needs

### Identity Sources
- **Registry**: Pre-configured identity → permission mappings
- **Factories**: Pattern-based dynamic permission assignment
- **Admin Bootstrap**: One-time admin identity initialization

### Security Controls
- **Automatic Token Refresh**: Transparent renewal when <20% TTL remains
- **Rate Limiting**: Configurable per-identity request limits
- **Factory Kill Switch**: Instant disable for compromised patterns
- **Short-Lived Tokens**: Default 15-minute TTL reduces exposure

### Edge Cases Handled
The [demo](demo/) extensively tests:
- One-time admin bootstrap enforcement
- Unregistered certificate rejection
- Factory pattern matching precedence
- Rate limit enforcement
- Automatic token refresh behavior
- Permission-based access control

## Deployment Considerations

### Certificate Management
SCTX relies on your existing PKI:
- Requires CA certificate pool for client validation
- Extracts identity from certificate CN or SAN
- Does not handle certificate revocation (use infrastructure layer)

### Storage
Currently implements in-memory storage for:
- Active tokens (cleaned up on expiry)
- Registry entries
- Factory configurations

Production deployments should consider:
- Service restart implications (clients will request new tokens)
- Clustering requirements (no built-in state synchronization)
- External session storage if needed

### Security Model
- **Zero Trust**: Every request requires valid certificate
- **Default Deny**: Unregistered identities rejected
- **Least Privilege**: Minimal permissions per identity
- **Admin Isolation**: Control operations require admin context

## Demo

See the [demo/](demo/) directory for a complete working example with:
- Certificate generation using minica
- Server implementation with all features
- Client test scenarios covering edge cases
- Docker Compose setup for easy execution

Run the demo:
```bash
cd demo
make test  # Run all security tests
```

## Examples

See the [USE_CASES.md](USE_CASES.md) file for comprehensive real-world examples:
- **API Gateway**: Service authentication and authorization
- **Microservices Mesh**: Service-to-service authentication  
- **Monorepo Security**: Package-level security boundaries
- **Development Environment**: Dynamic permissions with factories
- **Government Deployment**: FIPS-compliant configuration
- **Edge Computing**: Performance-optimized deployment

## API Reference

### Core Types
- **`ContextService[M]`** - Main service for issuing tokens with metadata type
- **`ServiceAdmin[M]`** - Administrative control interface with metadata support
- **`Token`** - Issued security context token with expiration tracking
- **`ContextData`** - Decoded token payload with permissions and identity
- **`ContextFactory`** - Pattern-based permission rules for dynamic environments
- **`RegistryEntry`** - Static identity permissions for known services
- **`CryptoAlgorithm`** - Algorithm selection (Ed25519 or ECDSA P-256)

### Configuration Types
- **`ContextServiceConfig`** - Service bootstrap configuration
  - `CAPool`: Certificate authority pool for validation
  - `PrivateKey`: Service private key (Ed25519 or ECDSA)
  - `Algorithm`: Cryptographic algorithm selection
  - `Registry`: Service identity registry
  - `AdminIdentity`: Expected admin certificate identity
  - `ContextTTL`: Token time-to-live duration

### Key Methods

**Service Lifecycle**
- **`Bootstrap(config, metadata)`** - Initialize service with admin authentication
- **`CompleteBootstrap()`** - Finalize service configuration (admin-only)
- **`GetService()`** - Get context service instance (admin-only)
- **`Shutdown()`** - Gracefully shutdown service

**Authentication & Authorization**  
- **`RequestContext(cert)`** - Issue token for mTLS certificate
- **`VerifyContext(context, publicKey)`** - Validate and decode token
- **`CheckCompatibility(caller, subject, publicKey)`** - Verify delegation permissions

**Service Management (Admin-only)**
- **`RegisterIdentity(name, entry)`** - Add service to registry
- **`RegisterFactory(factory)`** - Add pattern-based permission rules
- **`DisableFactory(id)`** - Emergency disable factory (kill switch)
- **`GetStats()`** - Retrieve service operational statistics

**Cryptographic Operations**
- **`GenerateKeyPair(algorithm)`** - Generate key pair for specified algorithm
- **`DetectAlgorithmFromPublicKey(key)`** - Automatically detect algorithm from public key
- **`ValidateAlgorithm(algorithm)`** - Verify algorithm is supported

## Design Decisions

### Why Configurable Cryptography?
**Performance vs. Compliance**: Ed25519 provides 25% better performance but ECDSA P-256 is required for FIPS 140-2 compliance. SCTX lets you choose based on your requirements without changing application code.

### Why Ed25519 as Default?
**Performance First**: Most applications benefit more from 25% faster verification than FIPS compliance. Government and regulated industries can explicitly choose ECDSA P-256 when needed.

### Why Admin-Only Control?
**Point of Control**: Security configuration cannot be modified by compromised services. Only authenticated admin contexts can alter the security posture, preventing lateral movement attacks.

### Why No Token Revocation?
**Simplicity and Security**: Tokens are ephemeral (15-minute default) and certificate revocation is handled by your PKI infrastructure. This simplifies the design while maintaining security.

### Why Pattern-Based Factories?
**Dynamic Environments**: Factories enable environments where services may not be pre-registered. Patterns like `*.dev.local` can grant appropriate permissions without manual configuration, perfect for development and CI/CD.

## Contributing

We welcome contributions that maintain SCTX's focus on security, performance, and simplicity!

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines including:
- **Development Setup**: Go 1.23+, testing tools, and environment configuration
- **Security Requirements**: Guidelines for security-critical code contributions
- **Performance Testing**: Benchmark requirements and regression detection
- **Commit Conventions**: Conventional commits for automated semantic versioning
- **Pull Request Process**: Review requirements and CI/CD integration

### Quick Contribution Checklist
- [ ] Tests pass (`go test ./...`)
- [ ] Benchmarks don't regress significantly
- [ ] Security tests cover edge cases
- [ ] Documentation updated for new features
- [ ] Conventional commit messages used
- [ ] No breaking changes without justification

### Performance Contributions
Algorithm performance improvements are especially welcome:
```bash
# Before changes
go test -bench=. -benchmem > before.bench

# After changes
go test -bench=. -benchmem > after.bench

# Compare performance
benchcmp before.bench after.bench
```

### Security Contributions
Security improvements require special attention:
- Coordinate with maintainers for vulnerability fixes
- Include comprehensive security tests
- Document threat model implications
- Follow responsible disclosure for security issues

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

[License details here]