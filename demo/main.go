package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/zoobzio/sctx"
)

const (
	serverPort = ":8443"
	adminPort  = ":8444"
)

// DemoMetadata shows request context metadata
type DemoMetadata struct {
	RequestID string `json:"request_id"`
	ClientIP  string `json:"client_ip"`
}

var (
	contextService *sctx.ContextService[DemoMetadata]
	serviceAdmin   *sctx.ServiceAdmin[DemoMetadata]
	caPool         *x509.CertPool
	privateKey     *ecdsa.PrivateKey
)

func main() {
	log.Println("=== SCTX Security Demo ===")
	
	// Load certificates and keys
	if err := loadCertificates(); err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	// Bootstrap the context service
	if err := bootstrapService(); err != nil {
		log.Fatalf("Failed to bootstrap service: %v", err)
	}

	// Export public key for services to use
	exportPrivateKey()
	log.Println("✓ Exported signing keys for service verification")

	// Start the servers
	go startHealthServer()
	go startAdminServer()
	startMainServer()
}

func loadCertificates() error {
	log.Println("Loading certificates...")
	
	// Load CA certificate
	caCert, err := os.ReadFile("certs/minica.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}
	
	caPool = x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA cert")
	}
	
	// Generate ECDSA P-256 private key for signing contexts
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	
	log.Println("✓ Loaded CA certificate")
	log.Println("✓ Generated P-256 signing key")
	return nil
}

func bootstrapService() error {
	log.Println("\n=== Bootstrapping SCTX Service ===")
	
	config := sctx.ContextServiceConfig{
		CAPool:        caPool,
		PrivateKey:    privateKey,
		Registry:      createMemoryRegistry(),
		IssuerName:    "sctx-demo",
		ContextTTL:    30 * time.Second, // Short TTL for demo
		AdminIdentity: "sctx-admin",
	}
	
	log.Printf("Admin identity: %s", config.AdminIdentity)
	log.Printf("Context TTL: %s", config.ContextTTL)
	
	// Create demo metadata template
	metadata := DemoMetadata{
		RequestID: "demo-init",
		ClientIP:  "127.0.0.1",
	}
	
	// Bootstrap the service
	admin, err := sctx.Bootstrap(config, metadata)
	if err != nil {
		return fmt.Errorf("bootstrap failed: %w", err)
	}
	
	serviceAdmin = admin
	contextService = admin.GetService()
	
	log.Println("✓ Service bootstrapped successfully")
	
	// Setup initial configuration
	return setupInitialConfiguration()
}

func setupInitialConfiguration() error {
	log.Println("\n=== Setting up initial configuration ===")
	
	// Register some identities in the registry
	log.Println("Registering known identities...")
	
	entries := map[string]sctx.RegistryEntry{
		// Microservices for realistic demo
		"order-service": {
			Type:        "service",
			Permissions: []string{"api:read", "api:write", "payments:process"},
		},
		"payment-service": {
			Type:        "service",
			Permissions: []string{"payments:process"},
		},
		// Legacy test clients
		"client-app-1": {
			Type:        "service",
			Permissions: []string{"api:read", "api:write"},
		},
		"client-app-2": {
			Type:        "service",
			Permissions: []string{"api:read"},
		},
		"service-mesh-gateway": {
			Type:        "gateway",
			Permissions: []string{"api:read", "api:write", "api:admin"},
		},
	}
	
	for identity, entry := range entries {
		if err := serviceAdmin.RegisterIdentity(identity, entry); err != nil {
			return fmt.Errorf("failed to register %s: %w", identity, err)
		}
		log.Printf("✓ Registered: %s with permissions %v", identity, entry.Permissions)
	}
	
	// Register context factories for pattern matching
	log.Println("\nRegistering context factories...")
	
	// Create factories using the constructor
	devFactory, err := sctx.NewContextFactory("dev-environment", "CN", `^dev\.(.+)\.local$`, "development", []string{"dev:debug", "dev:logs"}, 0)
	if err != nil {
		return fmt.Errorf("failed to create dev factory: %w", err)
	}
	devFactory.AllowRefresh = true
	devFactory.MaxRefreshes = intPtr(10)
	
	prodFactory, err := sctx.NewContextFactory("prod-environment", "CN", `^prod\.(.+)\.local$`, "production", []string{"prod:read"}, 0)
	if err != nil {
		return fmt.Errorf("failed to create prod factory: %w", err)
	}
	prodFactory.AllowRefresh = true
	prodFactory.MaxRefreshes = intPtr(2)
	
	teamFactory, err := sctx.NewContextFactory("team-services", "CN", `\.(team-[^.]+)\.local$`, "team", []string{"team:collaborate"}, 0)
	if err != nil {
		return fmt.Errorf("failed to create team factory: %w", err)
	}
	teamFactory.AllowRefresh = false
	
	factories := []*sctx.ContextFactory{devFactory, prodFactory, teamFactory}
	
	for _, factory := range factories {
		if err := serviceAdmin.RegisterFactory(factory); err != nil {
			return fmt.Errorf("failed to register factory %s: %w", factory.ID, err)
		}
		log.Printf("✓ Registered factory: %s (pattern: %s)", factory.ID, factory.MatchPattern)
	}
	
	// Lock factory registration
	log.Println("\nLocking factory registration...")
	if err := serviceAdmin.LockFactoryRegistration(); err != nil {
		return fmt.Errorf("failed to lock factories: %w", err)
	}
	log.Println("✓ Factory registration locked")
	
	// Complete bootstrap
	log.Println("\nCompleting bootstrap...")
	if err := serviceAdmin.CompleteBootstrap(); err != nil {
		return fmt.Errorf("failed to complete bootstrap: %w", err)
	}
	log.Println("✓ Bootstrap completed - admin identity is now locked")
	
	// Register processors for request handling
	log.Println("\nRegistering processors...")
	return setupProcessors()
}

func startMainServer() {
	mux := http.NewServeMux()
	
	// Health check endpoint (no client cert required)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := contextService.HealthCheck(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("OK"))
	})
	
	// Context request endpoint (requires client cert)
	mux.HandleFunc("/context", handleContextRequest)
	
	// Token validation endpoint (demonstrates how to verify tokens)
	mux.HandleFunc("/validate", handleValidateToken)
	
	// Demo endpoint that checks permissions
	mux.HandleFunc("/api/data", handleAPIRequest)
	
	// Server configuration with mTLS
	serverCert, err := tls.LoadX509KeyPair(
		"certs/sctx-service.local/cert.pem",
		"certs/sctx-service.local/key.pem",
	)
	if err != nil {
		log.Fatalf("Failed to load server cert: %v", err)
	}
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	
	server := &http.Server{
		Addr:      serverPort,
		Handler:   loggingMiddleware(mux),
		TLSConfig: tlsConfig,
	}
	
	log.Printf("\n=== Main server listening on %s ===", serverPort)
	log.Println("Endpoints:")
	log.Println("  - /health   (health check)")
	log.Println("  - /context  (request context token)")
	log.Println("  - /validate (validate token)")
	log.Println("  - /api/data (demo API endpoint)")
	
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func startAdminServer() {
	mux := http.NewServeMux()
	
	// Admin endpoints
	mux.HandleFunc("/stats", handleAdminStats)
	mux.HandleFunc("/factories", handleListFactories)
	mux.HandleFunc("/disable-factory", handleDisableFactory)
	mux.HandleFunc("/enable-factory", handleEnableFactory)
	
	// Admin server configuration
	serverCert, err := tls.LoadX509KeyPair(
		"certs/sctx-service.local/cert.pem",
		"certs/sctx-service.local/key.pem",
	)
	if err != nil {
		log.Fatalf("Failed to load server cert: %v", err)
	}
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	
	server := &http.Server{
		Addr:      adminPort,
		Handler:   loggingMiddleware(requireAdmin(mux)),
		TLSConfig: tlsConfig,
	}
	
	log.Printf("\n=== Admin server listening on %s ===", adminPort)
	log.Println("Admin endpoints:")
	log.Println("  - /stats    (service statistics)")
	log.Println("  - /factories (list factories)")
	log.Println("  - /disable-factory?id=xxx")
	log.Println("  - /enable-factory?id=xxx")
	
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Admin server failed: %v", err)
	}
}

func startHealthServer() {
	mux := http.NewServeMux()
	
	// Simple health check without TLS
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := contextService.HealthCheck(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("OK"))
	})
	
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	
	log.Println("\n=== Health server listening on :8080 ===")
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Health server failed: %v", err)
	}
}

func handleContextRequest(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "No client certificate provided", http.StatusUnauthorized)
		return
	}
	
	// Request context token
	token, err := contextService.RequestContext(r.TLS.PeerCertificates[0])
	if err != nil {
		log.Printf("Context request failed: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	
	// Return token information
	response := fmt.Sprintf("Token issued:\n")
	response += fmt.Sprintf("Context: %s\n", token.Context())
	response += fmt.Sprintf("Expires: %s\n", token.ExpiresAt().Format(time.RFC3339))
	
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))
}

func handleValidateToken(w http.ResponseWriter, r *http.Request) {
	// Get token from request
	tokenStr := r.Header.Get("X-Context-Token")
	if tokenStr == "" {
		http.Error(w, "No token provided", http.StatusBadRequest)
		return
	}
	
	// Get public key for verification
	publicKey := serviceAdmin.GetPublicKey()
	
	// Verify the token
	data, err := sctx.VerifyContext(sctx.Context(tokenStr), publicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return
	}
	
	// Return token data
	response := fmt.Sprintf("Valid token:\n")
	response += fmt.Sprintf("ID: %s\n", data.ID)
	response += fmt.Sprintf("Type: %s\n", data.Type)
	response += fmt.Sprintf("Permissions: %v\n", data.Permissions)
	response += fmt.Sprintf("Issued: %s\n", data.IssuedAt.Format(time.RFC3339))
	response += fmt.Sprintf("Expires: %s\n", data.ExpiresAt.Format(time.RFC3339))
	response += fmt.Sprintf("Context ID: %s\n", data.ContextID)
	response += fmt.Sprintf("Refresh Count: %d\n", data.RefreshCount)
	
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))
}

func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	// This demonstrates using the context token for authorization
	tokenStr := r.Header.Get("X-Context-Token")
	if tokenStr == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}
	
	// Verify token
	publicKey := serviceAdmin.GetPublicKey()
	data, err := sctx.VerifyContext(sctx.Context(tokenStr), publicKey)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	
	// Check permissions
	hasRead := false
	hasWrite := false
	for _, perm := range data.Permissions {
		if perm == "api:read" {
			hasRead = true
		}
		if perm == "api:write" {
			hasWrite = true
		}
	}
	
	if r.Method == "GET" && !hasRead {
		http.Error(w, "Missing api:read permission", http.StatusForbidden)
		return
	}
	
	if r.Method == "POST" && !hasWrite {
		http.Error(w, "Missing api:write permission", http.StatusForbidden)
		return
	}
	
	response := fmt.Sprintf("API access granted!\n")
	response += fmt.Sprintf("Identity: %s\n", data.ID)
	response += fmt.Sprintf("Permissions: %v\n", data.Permissions)
	
	w.Write([]byte(response))
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	stats := serviceAdmin.GetStats()
	
	response := fmt.Sprintf("Service Statistics:\n")
	response += fmt.Sprintf("Active Factories: %d\n", stats.ActiveFactories)
	response += fmt.Sprintf("Active Tokens: %d\n", stats.ActiveTokens)
	response += fmt.Sprintf("Admin Bootstrapped: %v\n", stats.AdminBootstrapped)
	
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))
}

func handleListFactories(w http.ResponseWriter, r *http.Request) {
	factories, err := serviceAdmin.ListFactories()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	response := "Registered Factories:\n\n"
	for _, f := range factories {
		response += fmt.Sprintf("ID: %s\n", f.ID)
		response += fmt.Sprintf("  Match Field: %s\n", f.MatchField)
		response += fmt.Sprintf("  Match Pattern: %s\n", f.MatchPattern)
		response += fmt.Sprintf("  Type: %s\n", f.ContextType)
		response += fmt.Sprintf("  Enabled: %v\n", f.Enabled)
		response += fmt.Sprintf("  Issued Count: %d\n", f.IssuedCount)
		if f.LastUsed != nil {
			response += fmt.Sprintf("  Last Used: %s\n", f.LastUsed.Format(time.RFC3339))
		}
		response += "\n"
	}
	
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))
}

func handleDisableFactory(w http.ResponseWriter, r *http.Request) {
	factoryID := r.URL.Query().Get("id")
	if factoryID == "" {
		http.Error(w, "Missing factory ID", http.StatusBadRequest)
		return
	}
	
	if err := serviceAdmin.DisableFactory(factoryID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	w.Write([]byte(fmt.Sprintf("Factory %s disabled\n", factoryID)))
}

func handleEnableFactory(w http.ResponseWriter, r *http.Request) {
	factoryID := r.URL.Query().Get("id")
	if factoryID == "" {
		http.Error(w, "Missing factory ID", http.StatusBadRequest)
		return
	}
	
	if err := serviceAdmin.EnableFactory(factoryID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	w.Write([]byte(fmt.Sprintf("Factory %s enabled\n", factoryID)))
}

// Middleware to log requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := "anonymous"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			identity = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		log.Printf("[%s] %s %s %s", r.RemoteAddr, identity, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// Middleware to require admin certificate
func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "No client certificate", http.StatusUnauthorized)
			return
		}
		
		// For demo, we just check if it's the admin cert
		// In production, you'd verify the context token has admin permissions
		if r.TLS.PeerCertificates[0].Subject.CommonName != "sctx-admin" {
			http.Error(w, "Not authorized for admin operations", http.StatusForbidden)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func intPtr(i int) *int {
	return &i
}

// createMemoryRegistry creates a registry for demo purposes
func createMemoryRegistry() sctx.Registry {
	return sctx.NewMemoryRegistry()
}

func setupProcessors() error {
	// Get operations interface for processors
	ops := serviceAdmin.GetOperations()
	
	// Create basic processors for demo
	securityProcessor := sctx.NewSecurityProcessor[DemoMetadata](ops)
	
	// Register minimal pipeline for registry-based authentication
	serviceAdmin.Register(
		securityProcessor.CertificateValidator(),
		securityProcessor.RegistryLookup(),
		securityProcessor.DefaultDeny(),
	)
	
	log.Println("✓ Processors registered successfully")
	return nil
}


// Helper to export private key for debugging
func exportPrivateKey() {
	derBytes, _ := x509.MarshalECPrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	
	os.WriteFile("demo-signing-key.pem", pemBytes, 0600)
	
	// Also export public key
	derPubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pemPubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPubBytes,
	}
	pemPubBytes := pem.EncodeToMemory(pemPubBlock)
	
	os.WriteFile("demo-signing-public.pem", pemPubBytes, 0644)
}