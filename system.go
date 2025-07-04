package sctx

import "slices"

// SystemContext represents security context for internal system components.
// This is used for internal services and package boundaries within the aegis framework.
type SystemContext struct {
	serviceName string
	permissions []string
	extensions  map[string]any
}

// NewSystemContext creates a security context for an internal system component
func NewSystemContext(serviceName string, permissions []string) *SystemContext {
	return &SystemContext{
		serviceName: "system:" + serviceName,
		permissions: permissions,
		extensions:  make(map[string]any),
	}
}

// GetID returns the service identifier with system prefix
func (s *SystemContext) GetID() string {
	return s.serviceName
}

// GetPermissions returns the list of permission scopes
func (s *SystemContext) GetPermissions() []string {
	return s.permissions
}

// HasPermission checks if the context includes a specific permission scope
func (s *SystemContext) HasPermission(scope string) bool {
	// System contexts with wildcard permissions have all permissions
	if slices.Contains(s.permissions, "*") {
		return true
	}
	return slices.Contains(s.permissions, scope)
}

// GetType returns SystemType for system contexts
func (s *SystemContext) GetType() ContextType {
	return SystemType
}

// IsSystem returns true for system contexts
func (s *SystemContext) IsSystem() bool {
	return true
}

// GetExtension retrieves a service-specific extension value
func (s *SystemContext) GetExtension(key string) (any, bool) {
	val, ok := s.extensions[key]
	return val, ok
}

// WithExtension returns a new context with an additional extension
func (s *SystemContext) WithExtension(key string, value any) Context {
	// Create a proper copy with new map
	newCtx := &SystemContext{
		serviceName: s.serviceName,
		permissions: s.permissions, // slices are ok to share for read-only
		extensions:  make(map[string]any),
	}

	// Copy existing extensions
	for k, v := range s.extensions {
		newCtx.extensions[k] = v
	}

	// Add new extension
	newCtx.extensions[key] = value
	return newCtx
}

// Internal context for trusted service-to-service communication
var Internal = &SystemContext{
	serviceName: "system:internal",
	permissions: []string{"*"}, // All permissions
	extensions:  make(map[string]any),
}