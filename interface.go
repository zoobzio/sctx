package sctx

// ContextType represents the type of security context
type ContextType string

const (
	// GuestType indicates an external user context
	GuestType ContextType = "guest"
	// SystemType indicates an internal system/service context
	SystemType ContextType = "system"
)

// Context represents the interface for security contexts in the aegis framework.
// It provides methods common to both guest (external user) and system (internal service) contexts.
type Context interface {
	// GetType returns the type of context (guest or system)
	GetType() ContextType

	// GetID returns the identity of the context owner
	GetID() string

	// GetPermissions returns the list of permission scopes
	GetPermissions() []string

	// HasPermission checks if the context includes a specific permission scope
	HasPermission(scope string) bool

	// IsSystem checks if this is a system/internal context
	IsSystem() bool

	// GetExtension retrieves a service-specific extension value
	GetExtension(key string) (any, bool)

	// WithExtension returns a new context with an additional extension
	WithExtension(key string, value any) Context
}