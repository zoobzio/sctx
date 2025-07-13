package sctx

import (
	"crypto"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/zoobzio/pipz"
)


var (
	ErrNotAdmin            = errors.New("invalid admin credentials")
	ErrNoServiceInstance   = errors.New("context service not initialized")
	ErrAlreadyBootstrapped = errors.New("system already bootstrapped")
)

// ServiceAdmin provides administrative control over the ContextService.
// It requires valid admin credentials to create and holds private access to the service.
type ServiceAdmin[M any] struct {
	service  *ContextService[M]
	pipeline *pipz.Contract[*ContextRequest[M]]
	created  time.Time
	mu       sync.RWMutex
}

// bootstrapOnce ensures bootstrap can only happen once
var (
	bootstrapOnce sync.Once
	bootstrapped  bool
	bootstrapErr  error
)

// Bootstrap initializes the context service and returns the first admin
// This is the ONLY way to create a context service - ensuring admin control from the start
func Bootstrap[M any](config ContextServiceConfig, metadata M) (*ServiceAdmin[M], error) {
	if bootstrapped {
		return nil, ErrAlreadyBootstrapped
	}

	var service *ContextService[M]

	bootstrapOnce.Do(func() {
		service, bootstrapErr = newContextService[M](config, metadata)
		if bootstrapErr == nil {
			bootstrapped = true
		}
	})

	if bootstrapErr != nil {
		return nil, bootstrapErr
	}

	admin := &ServiceAdmin[M]{
		service:  service,
		pipeline: pipz.NewContract[*ContextRequest[M]](),
		created:  time.Now(),
	}

	// Set admin reference in service
	service.admin = admin

	return admin, nil
}

// Register adds processors to the pipeline
// Processors are executed in the order they are registered
func (a *ServiceAdmin[M]) Register(processors ...PipelineProcessor[M]) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Convert to pipz.Processor format
	pipzProcessors := make([]pipz.Processor[*ContextRequest[M]], len(processors))
	for i, proc := range processors {
		pipzProcessors[i] = pipz.Processor[*ContextRequest[M]](proc)
	}

	// Register all processors
	a.pipeline.Register(pipzProcessors...)
}

// Deregister clears all processors
func (a *ServiceAdmin[M]) Deregister() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Create new empty pipeline
	a.pipeline = pipz.NewContract[*ContextRequest[M]]()
}


// RegisterFactory adds a new context factory
func (a *ServiceAdmin[M]) RegisterFactory(factory *ContextFactory) error {
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
func (a *ServiceAdmin[M]) RegisterIdentity(identity string, entry RegistryEntry) error {
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
func (a *ServiceAdmin[M]) LockFactoryRegistration() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.service.factoryManager.Lock()
	return nil
}

// CompleteBootstrap marks the admin bootstrap phase as complete
func (a *ServiceAdmin[M]) CompleteBootstrap() error {
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
func (a *ServiceAdmin[M]) RevokeToken(certificateFingerprint string) error {
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
func (a *ServiceAdmin[M]) GetMetrics() (*ServiceMetrics, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Get active token count
	activeTokens := 0
	if store, ok := a.service.tokenStore.(*memoryTokenStore); ok {
		activeTokens = store.Count()
	}

	return &ServiceMetrics{
		RegisteredIdentities: len(a.service.registry.List()),
		ActiveFactories:      len(a.service.factoryManager.ListFactories()),
		ActiveTokens:         activeTokens,
		BootstrapComplete:    a.service.adminBootstrapComplete,
		FactoriesLocked:      a.service.factoryManager.IsLocked(),
	}, nil
}

// DisableFactory disables a factory by ID (kill switch)
func (a *ServiceAdmin[M]) DisableFactory(factoryID string) error {
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
func (a *ServiceAdmin[M]) EnableFactory(factoryID string) error {
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
func (a *ServiceAdmin[M]) ListFactories() ([]*FactoryInfo, error) {
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
	ActiveFactories      int
	ActiveTokens         int
	BootstrapComplete    bool
	FactoriesLocked      bool
}

// GetPublicKey returns the service's public key for verification
// This is an admin-only operation
func (a *ServiceAdmin[M]) GetPublicKey() crypto.PublicKey {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.service.issuer.GetPublicKey()
}

// GetStats returns service statistics
// This is an admin-only operation
func (a *ServiceAdmin[M]) GetStats() ServiceStats {
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
func (a *ServiceAdmin[M]) GetService() *ContextService[M] {
	return a.service
}

// GetOperations returns admin-level operations interface for registered processors
// Since processors are registered by admin, they get admin-level access
func (a *ServiceAdmin[M]) GetOperations() Operations {
	return &adminOperations[M]{
		admin: a,
	}
}
