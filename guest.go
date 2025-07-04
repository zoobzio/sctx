package sctx

import "slices"

type GuestContext struct {
	userID      string
	permissions []string
	extensions  map[string]any
}

// NewGuestContext creates a security context for an authenticated external user
func NewGuestContext(userID string, permissions []string) *GuestContext {
	return &GuestContext{
		userID:      userID,
		permissions: permissions,
		extensions:  make(map[string]any),
	}
}

// GetID returns the user identifier
func (g *GuestContext) GetID() string {
	return g.userID
}

// GetPermissions returns the list of permission scopes
func (g *GuestContext) GetPermissions() []string {
	return g.permissions
}

// HasPermission checks if the context includes a specific permission scope
func (g *GuestContext) HasPermission(scope string) bool {
	return slices.Contains(g.permissions, scope)
}

// GetType returns GuestType for guest contexts
func (g *GuestContext) GetType() ContextType {
	return GuestType
}

// IsSystem returns false for guest contexts
func (g *GuestContext) IsSystem() bool {
	return false
}

// GetExtension retrieves a service-specific extension value
func (g *GuestContext) GetExtension(key string) (any, bool) {
	val, ok := g.extensions[key]
	return val, ok
}

// WithExtension returns a new context with an additional extension
func (g *GuestContext) WithExtension(key string, value any) Context {
	// Create a proper copy with new map
	newCtx := &GuestContext{
		userID:      g.userID,
		permissions: g.permissions, // slices are ok to share for read-only
		extensions:  make(map[string]any),
	}

	// Copy existing extensions
	for k, v := range g.extensions {
		newCtx.extensions[k] = v
	}

	// Add new extension
	newCtx.extensions[key] = value
	return newCtx
}
