package sctx

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotAdmin          = errors.New("invalid admin credentials")
	ErrNoServiceInstance = errors.New("context service not initialized")
	ErrAlreadyBootstrapped = errors.New("system already bootstrapped")
)

// ServiceAdmin provides administrative control over the ContextService.
// It requires valid admin credentials to create and holds private access to the service.
type ServiceAdmin struct {
	service *ContextService
	created time.Time
	mu      sync.Mutex
}

// bootstrapOnce ensures bootstrap can only happen once
var bootstrapOnce sync.Once
var bootstrapErr error

// Bootstrap initializes the context service and returns the first admin
// This is the ONLY way to create a context service - ensuring admin control from the start
func Bootstrap(config ContextServiceConfig) (*ServiceAdmin, error) {
	var admin *ServiceAdmin
	
	bootstrapOnce.Do(func() {
		// Create the service (using private constructor)
		service, err := newContextService(config)
		if err != nil {
			bootstrapErr = err
			return
		}
		
		// Create the first admin
		// The admin token will be created on first RequestContext
		// when the admin identity matches
		admin = &ServiceAdmin{
			service: service,
			created: time.Now(),
		}
	})
	
	if bootstrapErr != nil {
		return nil, bootstrapErr
	}
	
	if admin == nil {
		return nil, ErrAlreadyBootstrapped
	}
	
	return admin, nil
}

// NewServiceAdmin creates an admin instance after verifying credentials
// This is the ONLY way to perform administrative operations on the service
func NewServiceAdmin(service *ContextService, adminContext Context) (*ServiceAdmin, error) {
	if service == nil {
		return nil, ErrNoServiceInstance
	}
	
	// Verify the admin context using the service's internal key
	data, err := decodeAndVerify(adminContext, service.issuer.GetPublicKey())
	if err != nil {
		return nil, ErrNotAdmin
	}
	
	// Check if this is the expected admin identity
	if data.ID != service.adminIdentity {
		return nil, ErrNotAdmin
	}
	
	// Check admin permissions
	if !data.HasPermission("sctx:register") {
		return nil, ErrNotAdmin
	}
	
	return &ServiceAdmin{
		service: service,
		created: time.Now(),
	}, nil
}

// RegisterFactory adds a new context factory
func (a *ServiceAdmin) RegisterFactory(factory *ContextFactory) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	if a.service.factoryManager.IsLocked() {
		return errors.New("factory registration window has closed")
	}
	
	// Validate no wildcard permissions
	for _, perm := range factory.Permissions {
		if perm == "*" || strings.Contains(perm, "*") {
			return errors.New("wildcard permissions are not allowed")
		}
	}
	
	// Register with factory manager
	return a.service.factoryManager.RegisterFactory(factory)
}

// RegisterIdentity adds a specific identity to the registry
func (a *ServiceAdmin) RegisterIdentity(identity string, entry RegistryEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	// Validate no wildcard permissions
	for _, perm := range entry.Permissions {
		if perm == "*" || strings.Contains(perm, "*") {
			return errors.New("wildcard permissions are not allowed")
		}
	}
	
	return a.service.registry.Register(identity, entry)
}

// LockFactoryRegistration prevents any new factories from being registered
func (a *ServiceAdmin) LockFactoryRegistration() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	a.service.factoryManager.Lock()
	return nil
}

// CompleteBootstrap marks the admin bootstrap phase as complete
func (a *ServiceAdmin) CompleteBootstrap() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	// Mark bootstrap as complete
	a.service.adminBootstrapComplete = true
	a.service.factoryManager.Lock()
	
	// Ensure the sync.Once has been triggered
	// This prevents any future admin context creation
	a.service.adminBootstrapOnce.Do(func() {
		// No-op, just ensuring it's been called
	})
	
	return nil
}

// RevokeToken revokes an active token by removing it from the active list
func (a *ServiceAdmin) RevokeToken(certificateFingerprint string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	token, exists := a.service.tokenStore.Get(certificateFingerprint)
	if !exists {
		return errors.New("no active token for this certificate")
	}
	_ = token // avoid unused variable
	
	return a.service.tokenStore.Delete(certificateFingerprint)
}


// GetMetrics returns current service metrics
func (a *ServiceAdmin) GetMetrics() (*ServiceMetrics, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	// Get active token count
	activeTokens := 0
	if store, ok := a.service.tokenStore.(*memoryTokenStore); ok {
		activeTokens = store.Count()
	}
	
	return &ServiceMetrics{
		RegisteredIdentities: len(a.service.registry.List()),
		ActiveFactories:     len(a.service.factoryManager.ListFactories()),
		ActiveTokens:        activeTokens,
		BootstrapComplete:   a.service.adminBootstrapComplete,
		FactoriesLocked:     a.service.factoryManager.IsLocked(),
	}, nil
}

// DisableFactory disables a factory by ID (kill switch)
func (a *ServiceAdmin) DisableFactory(factoryID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	factory, exists := a.service.factoryManager.GetFactory(factoryID)
	if !exists {
		return errors.New("factory not found")
	}
	
	factory.Enabled = false
	return nil
}

// EnableFactory re-enables a disabled factory
func (a *ServiceAdmin) EnableFactory(factoryID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	
	factory, exists := a.service.factoryManager.GetFactory(factoryID)
	if !exists {
		return errors.New("factory not found")
	}
	
	factory.Enabled = true
	return nil
}

// ListFactories returns information about all registered factories
func (a *ServiceAdmin) ListFactories() ([]*FactoryInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	var infos []*FactoryInfo
	for _, factory := range a.service.factoryManager.ListFactories() {
		factory.mu.Lock()
		info := &FactoryInfo{
			ID:           factory.ID,
			MatchField:   factory.MatchField,
			MatchPattern: factory.MatchPattern,
			ContextType:  factory.ContextType,
			Enabled:      factory.Enabled,
			IssuedCount:  factory.IssuedCount,
			LastUsed:     factory.LastUsed,
			ValidFrom:    factory.ValidFrom,
			ValidUntil:   factory.ValidUntil,
			MaxIssuances: factory.MaxIssuances,
		}
		factory.mu.Unlock()
		infos = append(infos, info)
	}
	
	return infos, nil
}

// FactoryInfo contains information about a context factory
type FactoryInfo struct {
	ID           string
	MatchField   string
	MatchPattern string
	ContextType  ContextType
	Enabled      bool
	IssuedCount  int
	LastUsed     *time.Time
	ValidFrom    *time.Time
	ValidUntil   *time.Time
	MaxIssuances *int
}

// ServiceMetrics contains operational metrics for the context service
type ServiceMetrics struct {
	RegisteredIdentities int
	ActiveFactories     int
	ActiveTokens        int
	BootstrapComplete   bool
	FactoriesLocked     bool
}


// GetPublicKey returns the service's public key for verification
// This is an admin-only operation
func (a *ServiceAdmin) GetPublicKey() *ecdsa.PublicKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	return a.service.issuer.GetPublicKey()
}

// GetStats returns service statistics
// This is an admin-only operation  
func (a *ServiceAdmin) GetStats() ServiceStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	activeFactories := 0
	for _, f := range a.service.factoryManager.ListFactories() {
		if f.IsActive() {
			activeFactories++
		}
	}
	
	// Get active token count
	activeTokens := 0
	if store, ok := a.service.tokenStore.(*memoryTokenStore); ok {
		activeTokens = store.Count()
	}
	
	return ServiceStats{
		ActiveFactories:   activeFactories,
		ActiveTokens:      activeTokens,
		AdminBootstrapped: a.service.adminBootstrapComplete,
	}
}

// GetService returns the context service for requesting contexts
// This allows the admin to get contexts like any other client
func (a *ServiceAdmin) GetService() *ContextService {
	return a.service
}