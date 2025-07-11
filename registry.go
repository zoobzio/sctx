package sctx

import (
	"errors"
	"sync"
)

// RegistryEntry defines the permissions for a registered identity
type RegistryEntry struct {
	Type        ContextType
	Permissions []string
}

// Registry defines the interface for looking up service permissions
type Registry interface {
	// Register adds or updates an identity's permissions
	Register(identity string, entry RegistryEntry) error
	
	// Lookup retrieves permissions for an identity
	Lookup(identity string) (*RegistryEntry, error)
	
	// Remove deletes an identity from the registry
	Remove(identity string) error
	
	// List returns all registered identities
	List() []string
}

// MemoryRegistry is a simple in-memory implementation of Registry
type MemoryRegistry struct {
	mu      sync.RWMutex
	entries map[string]RegistryEntry
}

// newMemoryRegistry creates a new in-memory registry (private)
func newMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{
		entries: make(map[string]RegistryEntry),
	}
}

// Register adds or updates an identity's permissions
func (r *MemoryRegistry) Register(identity string, entry RegistryEntry) error {
	if identity == "" {
		return errors.New("identity cannot be empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.entries[identity] = entry
	return nil
}

// Lookup retrieves permissions for an identity
func (r *MemoryRegistry) Lookup(identity string) (*RegistryEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	entry, exists := r.entries[identity]
	if !exists {
		return nil, errors.New("identity not found in registry")
	}
	
	// Return a copy to prevent external modification
	result := RegistryEntry{
		Type:        entry.Type,
		Permissions: make([]string, len(entry.Permissions)),
	}
	copy(result.Permissions, entry.Permissions)
	
	return &result, nil
}

// Remove deletes an identity from the registry
func (r *MemoryRegistry) Remove(identity string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.entries[identity]; !exists {
		return errors.New("identity not found in registry")
	}
	
	delete(r.entries, identity)
	return nil
}

// List returns all registered identities
func (r *MemoryRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	identities := make([]string, 0, len(r.entries))
	for identity := range r.entries {
		identities = append(identities, identity)
	}
	
	return identities
}

