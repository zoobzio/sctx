# SCTX - Security Context Service

SCTX provides certificate-based security context tokens for zero-trust architectures. It issues short-lived, signed tokens based on mTLS client certificate authentication.

## Core Concepts

### Point of Control
SCTX enforces a strict security model where all service configuration and management flows through an authenticated admin service. This "Point of Control" principle ensures:
- No global state or public configuration methods
- Service bootstrap requires admin credentials
- All administrative operations require valid admin context
- Complete isolation between control plane and data plane

### Security Context Tokens
Clients present X.509 certificates via mTLS and receive signed JWT-like tokens containing:
- Identity extracted from certificate CN/SAN
- Permissions based on registry entries or factory patterns
- Cryptographic signature for verification
- Short TTL with automatic refresh

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

## Features

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

## API Reference

### Core Types
- `ContextService` - Main service for issuing tokens
- `ServiceAdmin` - Administrative control interface
- `Token` - Issued security context token
- `ContextData` - Decoded token payload
- `ContextFactory` - Pattern-based permission rules
- `RegistryEntry` - Static identity permissions

### Key Methods
- `Bootstrap()` - Initialize service with admin
- `RequestContext()` - Issue token for certificate
- `VerifyContext()` - Validate and decode token
- `RegisterIdentity()` - Add identity to registry
- `RegisterFactory()` - Add pattern-based rules

## Design Decisions

### Why Admin-Only Control?
The Point of Control pattern ensures security configuration cannot be modified by compromised services. Only authenticated admin contexts can alter the security posture.

### Why No Token Revocation?
Tokens are ephemeral (15-minute default) and certificate revocation is handled by your PKI infrastructure. This simplifies the design while maintaining security.

### Why Pattern-Based Factories?
Factories enable dynamic environments where services may not be pre-registered. Patterns like `*.dev.local` can grant appropriate permissions without manual configuration.

## Contributing

This project prioritizes security and simplicity. Contributions should:
- Maintain the admin-only control principle
- Avoid adding public configuration methods
- Include tests for security-sensitive changes
- Document threat model implications

## License

[License details here]