package sctx

// AdminFactory creates a factory for admin identities.
// Matches patterns like "sctx-admin", "tenant-admin", "cluster-admin".
func AdminFactory(permissions []string) (*ContextFactory, error) {
	return NewContextFactory("admin", "CN", "^(.+)-admin$", "admin", permissions, 0)
}

// TenantFactory creates a factory for tenant identities.
// Matches patterns like "tenant-acme-corp", "tenant-widgets-inc".
func TenantFactory(permissions []string) (*ContextFactory, error) {
	return NewContextFactory("tenant", "CN", "^tenant-([a-zA-Z0-9-]+)$", "tenant", permissions, 0)
}

// ServiceAccountFactory creates a factory for service accounts.
// Matches patterns like "svc-billing", "svc-notifications", "svc-auth".
func ServiceAccountFactory(permissions []string) (*ContextFactory, error) {
	return NewContextFactory("service-account", "CN", "^svc-([a-zA-Z0-9-]+)$", "service", permissions, 0)
}

// UserFactory creates a factory for user identities.
// Matches patterns like "user-john.doe@company.com", "user-admin@tenant.com".
func UserFactory(permissions []string) (*ContextFactory, error) {
	return NewContextFactory("user", "CN", "^user-(.+)@(.+)$", "user", permissions, 0)
}

// APIClientFactory creates a factory for API clients.
// Matches patterns like "api-client-mobile-app", "api-client-partner-xyz".
func APIClientFactory(permissions []string) (*ContextFactory, error) {
	return NewContextFactory("api-client", "CN", "^api-client-([a-zA-Z0-9-]+)$", "client", permissions, 0)
}