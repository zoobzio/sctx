# SCTX Use Cases

This document showcases real-world use cases for SCTX (Security Context) service. Each example demonstrates how SCTX can solve common authentication and authorization challenges in modern distributed systems.

## API Gateway with Service Authentication

Implement zero-trust API gateway that authenticates services and validates permissions:

```go
package main

import (
    "crypto/x509"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/zoobzio/sctx"
)

type APIGateway struct {
    sctxService *sctx.ContextService[map[string]interface{}]
    publicKey   crypto.PublicKey
}

type APIRequest struct {
    Service     string
    Endpoint    string
    Method      string
    ContextToken string
}

// authenticateService validates the service's mTLS certificate and issues a context token
func (gw *APIGateway) authenticateService(clientCert *x509.Certificate) (*sctx.Token, error) {
    if clientCert == nil {
        return nil, fmt.Errorf("no client certificate provided")
    }
    
    // Request context token from SCTX service
    token, err := gw.sctxService.RequestContext(clientCert)
    if err != nil {
        return nil, fmt.Errorf("authentication failed: %w", err)
    }
    
    return token, nil
}

// authorizeRequest validates the context token and checks permissions
func (gw *APIGateway) authorizeRequest(req APIRequest) (*sctx.ContextData, error) {
    if req.ContextToken == "" {
        return nil, fmt.Errorf("missing context token")
    }
    
    // Verify the context token
    contextData, err := sctx.VerifyContext(sctx.Context(req.ContextToken), gw.publicKey)
    if err != nil {
        return nil, fmt.Errorf("invalid context token: %w", err)
    }
    
    // Check if the service has permission for this endpoint
    requiredPermission := fmt.Sprintf("%s:%s", req.Endpoint, strings.ToLower(req.Method))
    if !contextData.HasPermission(requiredPermission) {
        return nil, fmt.Errorf("insufficient permissions for %s", requiredPermission)
    }
    
    return contextData, nil
}

// handleAPIRequest processes incoming requests through the gateway
func (gw *APIGateway) handleAPIRequest(w http.ResponseWriter, r *http.Request) {
    // Authenticate service via mTLS
    clientCert := extractClientCert(r)
    token, err := gw.authenticateService(clientCert)
    if err != nil {
        http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
        return
    }
    
    // Build request context
    apiReq := APIRequest{
        Service:     clientCert.Subject.CommonName,
        Endpoint:    extractEndpoint(r.URL.Path),
        Method:      r.Method,
        ContextToken: string(token.Context()),
    }
    
    // Authorize the request
    contextData, err := gw.authorizeRequest(apiReq)
    if err != nil {
        http.Error(w, fmt.Sprintf("Authorization failed: %v", err), http.StatusForbidden)
        return
    }
    
    // Forward to backend service with context
    forwardToBackend(w, r, contextData)
}

// Usage in production
func main() {
    // Bootstrap SCTX service
    admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
        CAPool:        loadCAPool(),
        PrivateKey:    loadPrivateKey(),
        Algorithm:     sctx.CryptoEd25519, // High performance
        Registry:      createAPIGatewayRegistry(),
        AdminIdentity: "api-gateway-admin",
        ContextTTL:    15 * time.Minute,
    }, map[string]interface{}{
        "gateway": "production",
    })
    if err != nil {
        panic(err)
    }
    
    // Configure service permissions
    configureGatewayPermissions(admin)
    
    gateway := &APIGateway{
        sctxService: admin.GetService(),
        publicKey:   admin.GetPublicKey(),
    }
    
    http.HandleFunc("/", gateway.handleAPIRequest)
    fmt.Println("API Gateway running on :8443")
    http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil)
}

func createAPIGatewayRegistry() sctx.Registry {
    registry := sctx.NewMemoryRegistry()
    
    // Register known backend services
    registry.Register("order-service", sctx.RegistryEntry{
        Type:        "service",
        Permissions: []string{"orders:read", "orders:write", "inventory:read"},
    })
    
    registry.Register("payment-service", sctx.RegistryEntry{
        Type:        "service", 
        Permissions: []string{"payments:process", "orders:read"},
    })
    
    registry.Register("inventory-service", sctx.RegistryEntry{
        Type:        "service",
        Permissions: []string{"inventory:read", "inventory:write"},
    })
    
    return registry
}
```

## Microservices Service Mesh Authentication

Implement service-to-service authentication in a microservices architecture:

```go
package main

import (
    "context"
    "crypto/x509"
    "fmt"
    "time"

    "github.com/zoobzio/sctx"
)

type OrderService struct {
    client      *ServiceMeshClient
    sctxService *sctx.ContextService[map[string]interface{}]
}

type ServiceMeshClient struct {
    cert      *x509.Certificate
    publicKey crypto.PublicKey
    cache     map[string]*sctx.Token // Token cache
}

// requestServiceToken gets an authentication token for service-to-service calls
func (s *OrderService) requestServiceToken() (*sctx.Token, error) {
    token, err := s.sctxService.RequestContext(s.client.cert)
    if err != nil {
        return nil, fmt.Errorf("failed to get service token: %w", err)
    }
    
    // Cache token for reuse until expiration
    s.client.cache["service-token"] = token
    return token, nil
}

// callPaymentService makes an authenticated call to the payment service
func (s *OrderService) callPaymentService(ctx context.Context, orderID string, amount float64) error {
    // Get or refresh service token
    token, exists := s.client.cache["service-token"]
    if !exists || token.ExpiresAt().Before(time.Now().Add(5*time.Minute)) {
        var err error
        token, err = s.requestServiceToken()
        if err != nil {
            return err
        }
    }
    
    // Create payment request with context token
    req := PaymentRequest{
        OrderID: orderID,
        Amount:  amount,
        Context: string(token.Context()),
    }
    
    return s.sendPaymentRequest(ctx, req)
}

type PaymentService struct {
    publicKey crypto.PublicKey
}

type PaymentRequest struct {
    OrderID string  `json:"order_id"`
    Amount  float64 `json:"amount"`
    Context string  `json:"context"`
}

// processPayment validates the incoming context and processes the payment
func (p *PaymentService) processPayment(req PaymentRequest) error {
    // Verify the service context token
    contextData, err := sctx.VerifyContext(sctx.Context(req.Context), p.publicKey)
    if err != nil {
        return fmt.Errorf("invalid service context: %w", err)
    }
    
    // Verify the calling service has payment permissions
    if !contextData.HasPermission("payments:process") {
        return fmt.Errorf("service %s lacks payment permissions", contextData.ID)
    }
    
    // Log the authenticated service call
    fmt.Printf("Processing payment for order %s from service %s\n", 
        req.OrderID, contextData.ID)
    
    // Process the payment...
    return processPaymentWithProvider(req.OrderID, req.Amount)
}

// Example of service discovery with context validation
func (s *OrderService) discoverAndCallService(serviceName string, operation string) error {
    // Get service token
    token, err := s.requestServiceToken()
    if err != nil {
        return err
    }
    
    // Discover service endpoint
    endpoint, err := s.discoverService(serviceName)
    if err != nil {
        return err
    }
    
    // Make authenticated call
    return s.callServiceWithContext(endpoint, operation, token)
}

// Usage in microservices setup
func setupServiceMesh() {
    // Bootstrap SCTX for each service
    orderServiceAdmin := bootstrapOrderService()
    paymentServiceAdmin := bootstrapPaymentService()
    
    // Create service instances
    orderService := &OrderService{
        client:      createServiceClient("order-service"),
        sctxService: orderServiceAdmin.GetService(),
    }
    
    paymentService := &PaymentService{
        publicKey: paymentServiceAdmin.GetPublicKey(),
    }
    
    // Services can now make authenticated calls
    orderService.callPaymentService(context.Background(), "order-123", 99.99)
}
```

## Monorepo Package Security Boundaries

Create security boundaries between packages within a single application:

```go
package main

import (
    "fmt"
    "crypto/x509"
    
    "github.com/zoobzio/sctx"
)

type MonorepoSecurityContext struct {
    sctxService *sctx.ContextService[map[string]interface{}]
    publicKey   crypto.PublicKey
    packageCert map[string]*x509.Certificate
}

// PackageA represents a sensitive package (e.g., payment processing)
type PackageA struct {
    security *MonorepoSecurityContext
}

// PackageB represents another package (e.g., user management)
type PackageB struct {
    security *MonorepoSecurityContext
}

// requestPackageAccess gets a context token for cross-package calls
func (m *MonorepoSecurityContext) requestPackageAccess(fromPackage string) (*sctx.Token, error) {
    cert, exists := m.packageCert[fromPackage]
    if !exists {
        return nil, fmt.Errorf("package %s not registered", fromPackage)
    }
    
    return m.sctxService.RequestContext(cert)
}

// validatePackageAccess verifies a cross-package call is authorized
func (m *MonorepoSecurityContext) validatePackageAccess(contextToken string, requiredPermission string) (*sctx.ContextData, error) {
    contextData, err := sctx.VerifyContext(sctx.Context(contextToken), m.publicKey)
    if err != nil {
        return nil, fmt.Errorf("invalid package context: %w", err)
    }
    
    if !contextData.HasPermission(requiredPermission) {
        return nil, fmt.Errorf("package %s lacks permission %s", contextData.ID, requiredPermission)
    }
    
    return contextData, nil
}

// sensitiveOperation in PackageA requires authentication
func (a *PackageA) processPayment(amount float64, fromPackage string, contextToken string) error {
    // Validate the calling package has payment permissions
    contextData, err := a.security.validatePackageAccess(contextToken, "payments:process")
    if err != nil {
        return fmt.Errorf("unauthorized payment access: %w", err)
    }
    
    fmt.Printf("Package %s authorized to process payment of $%.2f\n", 
        contextData.ID, amount)
    
    // Process payment logic...
    return nil
}

// crossPackageCall demonstrates how Package B calls Package A
func (b *PackageB) initiatePayment(userID string, amount float64) error {
    // Get context token for this package
    token, err := b.security.requestPackageAccess("user-management")
    if err != nil {
        return err
    }
    
    // Create PackageA instance
    packageA := &PackageA{security: b.security}
    
    // Call PackageA with authentication
    return packageA.processPayment(amount, "user-management", string(token.Context()))
}

// Setup monorepo security boundaries
func setupMonorepoSecurity() *MonorepoSecurityContext {
    // Bootstrap SCTX service
    admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
        CAPool:        createInternalCAPool(),
        PrivateKey:    generateInternalKey(),
        Algorithm:     sctx.CryptoEd25519,
        Registry:      createPackageRegistry(),
        AdminIdentity: "monorepo-admin",
        ContextTTL:    1 * time.Hour, // Longer TTL for internal packages
    }, map[string]interface{}{
        "deployment": "monorepo",
    })
    if err != nil {
        panic(err)
    }
    
    // Generate certificates for each package
    packageCerts := map[string]*x509.Certificate{
        "user-management": generatePackageCert("user-management"),
        "payment-processing": generatePackageCert("payment-processing"),
        "inventory-service": generatePackageCert("inventory-service"),
        "audit-logging": generatePackageCert("audit-logging"),
    }
    
    return &MonorepoSecurityContext{
        sctxService: admin.GetService(),
        publicKey:   admin.GetPublicKey(),
        packageCert: packageCerts,
    }
}

func createPackageRegistry() sctx.Registry {
    registry := sctx.NewMemoryRegistry()
    
    // Define package permissions
    registry.Register("user-management", sctx.RegistryEntry{
        Type:        "package",
        Permissions: []string{"users:read", "users:write", "payments:process"},
    })
    
    registry.Register("payment-processing", sctx.RegistryEntry{
        Type:        "package",
        Permissions: []string{"payments:process", "audit:write"},
    })
    
    registry.Register("inventory-service", sctx.RegistryEntry{
        Type:        "package", 
        Permissions: []string{"inventory:read", "inventory:write"},
    })
    
    registry.Register("audit-logging", sctx.RegistryEntry{
        Type:        "package",
        Permissions: []string{"audit:write", "audit:read"},
    })
    
    return registry
}
```

## Development Environment with Dynamic Permissions

Use factories for dynamic development environment permission assignment:

```go
package main

import (
    "fmt"
    "regexp"
    "time"
    
    "github.com/zoobzio/sctx"
)

type DevelopmentEnvironment struct {
    admin   *sctx.ServiceAdmin[map[string]interface{}]
    service *sctx.ContextService[map[string]interface{}]
}

// setupDevelopmentFactories configures pattern-based permission assignment
func (dev *DevelopmentEnvironment) setupDevelopmentFactories() {
    // Developer workstation factory - full permissions
    devFactory := &sctx.ContextFactory{
        ID:           "developer-workstations",
        MatchField:   "CN",
        MatchPattern: `^dev\.(.+)\.local$`,
        Permissions:  []string{
            "api:read", "api:write", "debug:enable", 
            "logs:read", "metrics:read", "deploy:staging",
        },
        TTLOverride:  30 * time.Minute, // Longer for dev productivity
    }
    
    // CI/CD pipeline factory - deployment permissions
    ciFactory := &sctx.ContextFactory{
        ID:           "ci-cd-pipelines",
        MatchField:   "CN", 
        MatchPattern: `^ci\.(.+)\.build$`,
        Permissions:  []string{
            "deploy:staging", "deploy:production", "tests:run",
            "api:read", "metrics:read",
        },
        TTLOverride:  5 * time.Minute, // Short for security
    }
    
    // Testing environment factory - limited permissions
    testFactory := &sctx.ContextFactory{
        ID:           "test-environment",
        MatchField:   "CN",
        MatchPattern: `^test\.(.+)\.env$`,
        Permissions:  []string{"api:read", "tests:run"},
        TTLOverride:  15 * time.Minute,
    }
    
    // Production services factory - strict permissions
    prodFactory := &sctx.ContextFactory{
        ID:           "production-services",
        MatchField:   "CN",
        MatchPattern: `^prod\.(.+)\.service$`,
        Permissions:  []string{"api:read"}, // Read-only by default
        TTLOverride:  60 * time.Minute, // Longer for stability
    }
    
    // Register all factories
    dev.admin.RegisterFactory(devFactory)
    dev.admin.RegisterFactory(ciFactory)
    dev.admin.RegisterFactory(testFactory)
    dev.admin.RegisterFactory(prodFactory)
}

// demonstrateDynamicPermissions shows how certificates get different permissions
func (dev *DevelopmentEnvironment) demonstrateDynamicPermissions() {
    testCases := []struct {
        certificateCN string
        expectedMatch string
        shouldSucceed bool
    }{
        {"dev.alice.local", "developer-workstations", true},
        {"dev.bob.local", "developer-workstations", true},
        {"ci.main.build", "ci-cd-pipelines", true},
        {"test.integration.env", "test-environment", true},
        {"prod.api.service", "production-services", true},
        {"unknown.service", "", false},
    }
    
    for _, tc := range testCases {
        cert := generateCertWithCN(tc.certificateCN)
        token, err := dev.service.RequestContext(cert)
        
        if tc.shouldSucceed && err == nil {
            fmt.Printf("✓ %s matched factory %s\n", tc.certificateCN, tc.expectedMatch)
            
            // Verify context and show permissions
            context, _ := sctx.VerifyContext(token.Context(), dev.admin.GetPublicKey())
            fmt.Printf("  Permissions: %v\n", context.Permissions)
        } else if !tc.shouldSucceed && err != nil {
            fmt.Printf("✓ %s correctly rejected\n", tc.certificateCN)
        } else {
            fmt.Printf("✗ Unexpected result for %s\n", tc.certificateCN)
        }
    }
}

// emergencyDisableFactory demonstrates factory kill switch
func (dev *DevelopmentEnvironment) emergencyDisableFactory(factoryID string) {
    fmt.Printf("🚨 Emergency: Disabling factory %s\n", factoryID)
    
    // Admin can instantly disable compromised factories
    err := dev.admin.DisableFactory(factoryID)
    if err != nil {
        fmt.Printf("Failed to disable factory: %v\n", err)
        return
    }
    
    // Verify factory is disabled
    cert := generateCertWithCN("dev.compromised.local")
    _, err = dev.service.RequestContext(cert)
    if err != nil {
        fmt.Println("✓ Factory successfully disabled - certificates rejected")
    } else {
        fmt.Println("✗ Factory still accepting certificates")
    }
}

// auditFactoryUsage shows how to monitor factory usage
func (dev *DevelopmentEnvironment) auditFactoryUsage() {
    stats := dev.admin.GetStats()
    
    fmt.Printf("Active Factories: %d\n", stats.ActiveFactories)
    fmt.Printf("Active Tokens: %d\n", stats.ActiveTokens)
    
    // Get detailed factory information
    factories := dev.admin.ListFactories()
    for _, factory := range factories {
        fmt.Printf("Factory %s: %d active tokens\n", 
            factory.ID, factory.ActiveTokens)
    }
}

// Usage in development setup
func main() {
    // Bootstrap development environment
    admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
        CAPool:        loadDevelopmentCA(),
        PrivateKey:    loadDevelopmentKey(),
        Algorithm:     sctx.CryptoEd25519, // Fast for development
        Registry:      sctx.NewMemoryRegistry(),
        AdminIdentity: "dev-admin",
        ContextTTL:    15 * time.Minute,
    }, map[string]interface{}{
        "environment": "development",
    })
    if err != nil {
        panic(err)
    }
    
    dev := &DevelopmentEnvironment{
        admin:   admin,
        service: admin.GetService(),
    }
    
    // Configure dynamic permission patterns
    dev.setupDevelopmentFactories()
    
    // Complete bootstrap
    admin.CompleteBootstrap()
    
    // Demonstrate features
    dev.demonstrateDynamicPermissions()
    dev.auditFactoryUsage()
    
    // Simulate emergency response
    dev.emergencyDisableFactory("developer-workstations")
}
```

## High-Security Government Deployment

Example configuration for FIPS-compliant government deployment:

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "time"
    
    "github.com/zoobzio/sctx"
)

type GovernmentSecurityConfig struct {
    admin   *sctx.ServiceAdmin[GovernmentMetadata]
    service *sctx.ContextService[GovernmentMetadata]
}

type GovernmentMetadata struct {
    Classification string `json:"classification"`
    Clearance      string `json:"clearance"`
    Department     string `json:"department"`
    AuditID        string `json:"audit_id"`
}

// setupFIPSCompliantService configures SCTX for government use
func setupFIPSCompliantService() *GovernmentSecurityConfig {
    // Use ECDSA P-256 for FIPS 140-2 compliance (required for government)
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        panic(err)
    }
    
    admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
        CAPool:        loadGovernmentCAPool(), // Official DoD CA
        PrivateKey:    privateKey,
        Algorithm:     sctx.CryptoECDSAP256, // FIPS compliant
        Registry:      createClassifiedRegistry(),
        AdminIdentity: "security-admin",
        ContextTTL:    5 * time.Minute, // Short TTL for security
    }, GovernmentMetadata{
        Classification: "SECRET",
        Department:     "DoD",
        AuditID:        generateAuditID(),
    })
    if err != nil {
        panic(err)
    }
    
    return &GovernmentSecurityConfig{
        admin:   admin,
        service: admin.GetService(),
    }
}

func createClassifiedRegistry() sctx.Registry {
    registry := sctx.NewMemoryRegistry()
    
    // Top Secret clearance services
    registry.Register("ts-intelligence-service", sctx.RegistryEntry{
        Type:        "classified-service",
        Permissions: []string{
            "intelligence:read", "intelligence:write",
            "classified:ts", "audit:write",
        },
    })
    
    // Secret clearance services
    registry.Register("secret-logistics-service", sctx.RegistryEntry{
        Type:        "classified-service",
        Permissions: []string{
            "logistics:read", "logistics:write",
            "classified:secret", "audit:write",
        },
    })
    
    // Confidential services
    registry.Register("confidential-admin-service", sctx.RegistryEntry{
        Type:        "classified-service",
        Permissions: []string{
            "admin:read", "classified:confidential",
            "audit:write",
        },
    })
    
    return registry
}

// setupClassificationFactories creates clearance-based factories
func (gov *GovernmentSecurityConfig) setupClassificationFactories() {
    // Top Secret factory
    tsFactory := &sctx.ContextFactory{
        ID:           "top-secret-clearance",
        MatchField:   "CN",
        MatchPattern: `^ts\.(.+)\.mil$`,
        Permissions:  []string{
            "classified:ts", "classified:secret", "classified:confidential",
            "intelligence:read", "intelligence:write", "audit:write",
        },
        TTLOverride: 3 * time.Minute, // Very short for TS
    }
    
    // Secret factory
    secretFactory := &sctx.ContextFactory{
        ID:           "secret-clearance",
        MatchField:   "CN",
        MatchPattern: `^secret\.(.+)\.mil$`,
        Permissions:  []string{
            "classified:secret", "classified:confidential",
            "logistics:read", "logistics:write", "audit:write",
        },
        TTLOverride: 5 * time.Minute,
    }
    
    // Confidential factory
    confFactory := &sctx.ContextFactory{
        ID:           "confidential-clearance",
        MatchField:   "CN",
        MatchPattern: `^conf\.(.+)\.mil$`,
        Permissions:  []string{
            "classified:confidential", "admin:read", "audit:write",
        },
        TTLOverride: 10 * time.Minute,
    }
    
    gov.admin.RegisterFactory(tsFactory)
    gov.admin.RegisterFactory(secretFactory)
    gov.admin.RegisterFactory(confFactory)
}

// auditSecurityEvents logs all security events for compliance
func (gov *GovernmentSecurityConfig) auditSecurityEvents() {
    // Government deployments require comprehensive audit logging
    stats := gov.admin.GetStats()
    
    auditEvent := map[string]interface{}{
        "timestamp":       time.Now().UTC(),
        "active_tokens":   stats.ActiveTokens,
        "active_factories": stats.ActiveFactories,
        "classification":  "SECRET",
        "compliance":      "FIPS-140-2",
        "algorithm":       "ECDSA-P256",
    }
    
    // Log to government audit system
    logToGovAuditSystem(auditEvent)
}

func main() {
    // Setup FIPS-compliant government service
    gov := setupFIPSCompliantService()
    gov.setupClassificationFactories()
    
    // Enable comprehensive audit logging
    go func() {
        ticker := time.NewTicker(1 * time.Minute)
        for range ticker.C {
            gov.auditSecurityEvents()
        }
    }()
    
    fmt.Println("Government SCTX service running with FIPS 140-2 compliance")
    fmt.Println("Algorithm: ECDSA P-256")
    fmt.Println("Classification: SECRET")
    fmt.Println("Audit logging: ENABLED")
}
```

## Performance-Optimized Edge Deployment

Configure SCTX for high-performance edge computing with Ed25519:

```go
package main

import (
    "crypto/ed25519"
    "time"
    
    "github.com/zoobzio/sctx"
)

type EdgeDeployment struct {
    admin   *sctx.ServiceAdmin[EdgeMetadata]
    service *sctx.ContextService[EdgeMetadata]
}

type EdgeMetadata struct {
    EdgeLocation string    `json:"edge_location"`
    Region       string    `json:"region"`
    Performance  bool      `json:"performance_optimized"`
    Timestamp    time.Time `json:"timestamp"`
}

// setupHighPerformanceEdge configures SCTX for maximum performance
func setupHighPerformanceEdge() *EdgeDeployment {
    // Use Ed25519 for 30% better performance than ECDSA
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        panic(err)
    }
    
    admin, err := sctx.Bootstrap(sctx.ContextServiceConfig{
        CAPool:        loadEdgeCAPool(),
        PrivateKey:    privateKey,
        Algorithm:     sctx.CryptoEd25519, // Maximum performance
        Registry:      createEdgeRegistry(),
        AdminIdentity: "edge-admin",
        ContextTTL:    30 * time.Minute, // Longer TTL to reduce auth overhead
    }, EdgeMetadata{
        EdgeLocation:   "us-west-1a",
        Region:         "us-west-1",
        Performance:    true,
        Timestamp:      time.Now(),
    })
    if err != nil {
        panic(err)
    }
    
    return &EdgeDeployment{
        admin:   admin,
        service: admin.GetService(),
    }
}

func createEdgeRegistry() sctx.Registry {
    registry := sctx.NewMemoryRegistry()
    
    // High-frequency edge services
    registry.Register("cdn-edge-node", sctx.RegistryEntry{
        Type:        "edge-service",
        Permissions: []string{
            "cache:read", "cache:write", "cdn:serve",
            "metrics:write", "health:report",
        },
    })
    
    registry.Register("iot-gateway", sctx.RegistryEntry{
        Type:        "edge-service",
        Permissions: []string{
            "iot:ingest", "iot:route", "telemetry:write",
            "edge:process", "metrics:write",
        },
    })
    
    registry.Register("edge-analytics", sctx.RegistryEntry{
        Type:        "edge-service",
        Permissions: []string{
            "analytics:process", "data:aggregate",
            "metrics:write", "alerts:send",
        },
    })
    
    return registry
}

// setupPerformanceFactories creates latency-optimized factories
func (edge *EdgeDeployment) setupPerformanceFactories() {
    // Edge computing factory - optimized for speed
    edgeFactory := &sctx.ContextFactory{
        ID:           "edge-computing-nodes",
        MatchField:   "CN",
        MatchPattern: `^edge\.(.+)\.compute$`,
        Permissions:  []string{
            "edge:process", "cache:read", "cache:write",
            "iot:ingest", "analytics:process", "metrics:write",
        },
        TTLOverride: 60 * time.Minute, // Long TTL for performance
    }
    
    // IoT device factory
    iotFactory := &sctx.ContextFactory{
        ID:           "iot-devices",
        MatchField:   "CN",
        MatchPattern: `^iot\.(.+)\.device$`,
        Permissions:  []string{
            "iot:ingest", "telemetry:write", "health:report",
        },
        TTLOverride: 120 * time.Minute, // Very long for IoT efficiency
    }
    
    edge.admin.RegisterFactory(edgeFactory)
    edge.admin.RegisterFactory(iotFactory)
}

// benchmarkPerformance measures edge authentication performance
func (edge *EdgeDeployment) benchmarkPerformance() {
    cert := generateEdgeCert("edge.node-1.compute")
    
    // Measure authentication latency
    start := time.Now()
    for i := 0; i < 1000; i++ {
        _, err := edge.service.RequestContext(cert)
        if err != nil {
            fmt.Printf("Auth failed: %v\n", err)
            return
        }
    }
    elapsed := time.Since(start)
    
    fmt.Printf("Edge Performance Results:\n")
    fmt.Printf("- Algorithm: Ed25519 (performance optimized)\n")
    fmt.Printf("- 1000 authentications: %v\n", elapsed)
    fmt.Printf("- Average per auth: %v\n", elapsed/1000)
    fmt.Printf("- Throughput: %.0f auths/sec\n", 1000.0/elapsed.Seconds())
}

func main() {
    // Setup high-performance edge deployment
    edge := setupHighPerformanceEdge()
    edge.setupPerformanceFactories()
    
    // Benchmark performance characteristics
    edge.benchmarkPerformance()
    
    fmt.Println("High-performance edge SCTX deployment ready")
    fmt.Println("- Algorithm: Ed25519 (30% faster than ECDSA)")
    fmt.Println("- TTL: 30-120 minutes (optimized for edge)")
    fmt.Println("- Registry: In-memory (millisecond lookups)")
}
```

## Key Use Case Patterns

### 1. Authentication Flows
- **Certificate-based**: mTLS client certificates for service identity
- **Token-based**: Short-lived context tokens for request authorization
- **Dual-layer**: Certificate + token for defense in depth

### 2. Permission Models
- **Registry-based**: Pre-configured service permissions
- **Factory-based**: Pattern-matching dynamic permissions
- **Hybrid**: Registry for known services, factories for development

### 3. Performance Optimization
- **Ed25519**: 30% faster for high-throughput environments
- **ECDSA P-256**: FIPS compliance for government/regulated industries
- **TTL tuning**: Longer TTLs reduce authentication overhead

### 4. Security Patterns
- **Zero Trust**: Every request requires valid certificate + token
- **Least Privilege**: Minimal permissions per service/role
- **Admin Isolation**: Control plane separated from data plane
- **Emergency Response**: Factory kill switches for incident response

### 5. Operational Patterns
- **Service Mesh**: Transparent service-to-service authentication
- **API Gateway**: Centralized authentication and authorization
- **Development**: Dynamic permissions for developer productivity
- **Edge Computing**: Performance-optimized for latency-sensitive workloads

These use cases demonstrate SCTX's flexibility across different deployment scenarios while maintaining strong security principles.