package sctx

import (
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrAdminAlreadyExists = errors.New("service admin already exists")
	ErrNotAdmin          = errors.New("invalid admin credentials")
	ErrNoServiceInstance = errors.New("context service not initialized")
)

// ServiceAdmin provides administrative control over the ContextService.
// Only one admin instance can exist, and it requires valid admin credentials to create.
type ServiceAdmin struct {
	created time.Time
	mu      sync.Mutex
}

// Global admin singleton
var (
	adminInstance *ServiceAdmin
	adminOnce     sync.Once
	
	// Global service instance that admin controls
	globalContextService *ContextService
	serviceMu           sync.RWMutex
)

// InitializeContextService initializes the global context service instance
func InitializeContextService(config ContextServiceConfig) error {
	serviceMu.Lock()
	defer serviceMu.Unlock()
	
	if globalContextService != nil {
		return errors.New("context service already initialized")
	}
	
	svc, err := NewContextService(config)
	if err != nil {
		return err
	}
	
	globalContextService = svc
	return nil
}

// GetContextService returns the global context service instance
func GetContextService() (*ContextService, error) {
	serviceMu.RLock()
	defer serviceMu.RUnlock()
	
	if globalContextService == nil {
		return nil, ErrNoServiceInstance
	}
	
	return globalContextService, nil
}

// NewServiceAdmin creates the singleton admin instance after verifying credentials
func NewServiceAdmin(adminContext Context) (*ServiceAdmin, error) {
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return nil, ErrNoServiceInstance
	}
	
	// Verify the admin context using the service's internal key
	data, err := decodeAndVerify(adminContext, service.publicKey)
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
	
	var created bool
	adminOnce.Do(func() {
		adminInstance = &ServiceAdmin{
			created: time.Now(),
		}
		created = true
	})
	
	if !created {
		return nil, ErrAdminAlreadyExists
	}
	
	return adminInstance, nil
}

// RegisterFactory adds a new context factory
func (a *ServiceAdmin) RegisterFactory(factory *ContextFactory) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	if service.factoryRegistrationLocked {
		return errors.New("factory registration window has closed")
	}
	
	// Validate factory ID
	if factory.ID == "" {
		return errors.New("factory ID is required")
	}
	
	// Check for duplicate ID
	service.factoriesMu.RLock()
	for _, existing := range service.factories {
		if existing.ID == factory.ID {
			service.factoriesMu.RUnlock()
			return errors.New("factory ID already exists")
		}
	}
	service.factoriesMu.RUnlock()
	
	// Validate no wildcard permissions
	for _, perm := range factory.Permissions {
		if perm == "*" || strings.Contains(perm, "*") {
			return errors.New("wildcard permissions are not allowed")
		}
	}
	
	// Compile the factory regex
	if err := factory.Compile(); err != nil {
		return err
	}
	
	// Enable by default
	factory.Enabled = true
	
	service.factoriesMu.Lock()
	service.factories = append(service.factories, factory)
	service.factoriesMu.Unlock()
	return nil
}

// RegisterIdentity adds a specific identity to the registry
func (a *ServiceAdmin) RegisterIdentity(identity string, entry RegistryEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	// Validate no wildcard permissions
	for _, perm := range entry.Permissions {
		if perm == "*" || strings.Contains(perm, "*") {
			return errors.New("wildcard permissions are not allowed")
		}
	}
	
	return service.registry.Register(identity, entry)
}

// LockFactoryRegistration prevents any new factories from being registered
func (a *ServiceAdmin) LockFactoryRegistration() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	service.factoryRegistrationLocked = true
	return nil
}

// CompleteBootstrap marks the admin bootstrap phase as complete
func (a *ServiceAdmin) CompleteBootstrap() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	// Mark bootstrap as complete
	service.adminBootstrapComplete = true
	service.factoryRegistrationLocked = true
	
	// Ensure the sync.Once has been triggered
	// This prevents any future admin context creation
	service.adminBootstrapOnce.Do(func() {
		// No-op, just ensuring it's been called
	})
	
	return nil
}

// RevokeToken revokes an active token by removing it from the active list
func (a *ServiceAdmin) RevokeToken(certificateFingerprint string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	service.activeTokensMu.Lock()
	defer service.activeTokensMu.Unlock()
	
	if _, exists := service.activeTokens[certificateFingerprint]; !exists {
		return errors.New("no active token for this certificate")
	}
	
	delete(service.activeTokens, certificateFingerprint)
	return nil
}

// ListActiveTokens returns information about all active tokens
func (a *ServiceAdmin) ListActiveTokens() ([]*ActiveTokenInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return nil, ErrNoServiceInstance
	}
	
	var tokens []*ActiveTokenInfo
	service.activeTokensMu.RLock()
	for fingerprint, token := range service.activeTokens {
		tokens = append(tokens, &ActiveTokenInfo{
			CertificateFingerprint: fingerprint,
			ContextID:              token.ContextID,
			Identity:               token.Identity,
			IssuedAt:               token.IssuedAt,
			ExpiresAt:              token.ExpiresAt,
			Permissions:            token.Permissions,
			FactoryID:              token.FactoryID,
			RefreshCount:           token.RefreshCount,
		})
	}
	service.activeTokensMu.RUnlock()
	
	return tokens, nil
}

// GetMetrics returns current service metrics
func (a *ServiceAdmin) GetMetrics() (*ServiceMetrics, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return nil, ErrNoServiceInstance
	}
	
	service.activeTokensMu.RLock()
	activeTokens := len(service.activeTokens)
	service.activeTokensMu.RUnlock()
	
	return &ServiceMetrics{
		RegisteredIdentities: len(service.registry.List()),
		ActiveFactories:     len(service.factories),
		ActiveTokens:        activeTokens,
		BootstrapComplete:   service.adminBootstrapComplete,
		FactoriesLocked:     service.factoryRegistrationLocked,
	}, nil
}

// DisableFactory disables a factory by ID (kill switch)
func (a *ServiceAdmin) DisableFactory(factoryID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	service.factoriesMu.RLock()
	for _, factory := range service.factories {
		if factory.ID == factoryID {
			service.factoriesMu.RUnlock()
			factory.Enabled = false
			return nil
		}
	}
	service.factoriesMu.RUnlock()
	
	return errors.New("factory not found")
}

// EnableFactory re-enables a disabled factory
func (a *ServiceAdmin) EnableFactory(factoryID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return ErrNoServiceInstance
	}
	
	service.factoriesMu.RLock()
	for _, factory := range service.factories {
		if factory.ID == factoryID {
			service.factoriesMu.RUnlock()
			factory.Enabled = true
			return nil
		}
	}
	service.factoriesMu.RUnlock()
	
	return errors.New("factory not found")
}

// ListFactories returns information about all registered factories
func (a *ServiceAdmin) ListFactories() ([]*FactoryInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	serviceMu.RLock()
	service := globalContextService
	serviceMu.RUnlock()
	
	if service == nil {
		return nil, ErrNoServiceInstance
	}
	
	var infos []*FactoryInfo
	service.factoriesMu.RLock()
	for _, factory := range service.factories {
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
	service.factoriesMu.RUnlock()
	
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

// ActiveTokenInfo contains information about an active token
type ActiveTokenInfo struct {
	CertificateFingerprint string
	ContextID              string
	Identity               string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Permissions            []string
	FactoryID              string
	RefreshCount           int
}