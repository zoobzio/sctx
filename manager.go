package sctx

import (
	"crypto/x509"
	"errors"
	"sync"
)

// FactoryManager manages context factories and finds the best match for certificates
type FactoryManager interface {
	// FindBestFactory finds the highest priority factory that matches the certificate
	FindBestFactory(cert *x509.Certificate) (*ContextFactory, error)
	
	// RegisterFactory adds a new factory (only allowed before Lock)
	RegisterFactory(factory *ContextFactory) error
	
	// GetFactory retrieves a factory by ID
	GetFactory(id string) (*ContextFactory, bool)
	
	// Lock prevents any new factories from being registered
	Lock()
	
	// IsLocked returns whether factory registration is locked
	IsLocked() bool
	
	// ListFactories returns all registered factories
	ListFactories() []*ContextFactory
}

// defaultFactoryManager is the standard implementation of FactoryManager
type defaultFactoryManager struct {
	factories []*ContextFactory
	locked    bool
	mu        sync.RWMutex
}

// newFactoryManager creates a new factory manager (private)
func newFactoryManager() FactoryManager {
	return &defaultFactoryManager{
		factories: make([]*ContextFactory, 0),
	}
}

// FindBestFactory finds the highest priority factory that matches the certificate
func (m *defaultFactoryManager) FindBestFactory(cert *x509.Certificate) (*ContextFactory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var bestFactory *ContextFactory
	bestPriority := -1
	
	for _, factory := range m.factories {
		if !factory.IsActive() {
			continue
		}
		
		if matched, _ := factory.Match(cert); matched {
			if factory.Priority > bestPriority {
				bestFactory = factory
				bestPriority = factory.Priority
			}
		}
	}
	
	if bestFactory == nil {
		return nil, errors.New("no matching factory found")
	}
	
	return bestFactory, nil
}

// RegisterFactory adds a new factory
func (m *defaultFactoryManager) RegisterFactory(factory *ContextFactory) error {
	if factory == nil {
		return errors.New("factory cannot be nil")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.locked {
		return errors.New("factory registration is locked")
	}
	
	// Validate factory ID
	if factory.ID == "" {
		return errors.New("factory ID is required")
	}
	
	// Check for duplicate ID
	for _, existing := range m.factories {
		if existing.ID == factory.ID {
			return errors.New("factory ID already exists")
		}
	}
	
	// Compile the factory regex
	if err := factory.Compile(); err != nil {
		return err
	}
	
	// Enable by default
	factory.Enabled = true
	
	m.factories = append(m.factories, factory)
	return nil
}

// GetFactory retrieves a factory by ID
func (m *defaultFactoryManager) GetFactory(id string) (*ContextFactory, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	for _, factory := range m.factories {
		if factory.ID == id {
			return factory, true
		}
	}
	
	return nil, false
}

// Lock prevents any new factories from being registered
func (m *defaultFactoryManager) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = true
}

// IsLocked returns whether factory registration is locked
func (m *defaultFactoryManager) IsLocked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.locked
}

// ListFactories returns all registered factories
func (m *defaultFactoryManager) ListFactories() []*ContextFactory {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Return a copy to prevent external modification
	result := make([]*ContextFactory, len(m.factories))
	copy(result, m.factories)
	return result
}