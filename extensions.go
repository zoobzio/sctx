package sctx

import "time"

// Extensions holds all structured extension data for a security context
type Extensions struct {
	// Session information
	Session *SessionExt

	// Authentication details
	Auth *AuthExt

	// Rate limiting data
	RateLimit *RateLimitExt

	// Request tracing
	Trace *TraceExt

	// Service mesh information
	ServiceMesh *ServiceMeshExt

	// Custom extensions for service-specific data
	Custom map[string]any
}

// SessionExt contains session-related security data
type SessionExt struct {
	SessionID    string
	LoginTime    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
	IPAddress    string
	UserAgent    string
	DeviceID     string
}

// AuthExt contains authentication metadata
type AuthExt struct {
	Method         string   // "oauth", "saml", "password", "api_key"
	Provider       string   // "google", "okta", "internal"
	MFAVerified    bool
	MFAMethod      string   // "totp", "sms", "webauthn"
	Roles          []string
	Groups         []string
	OrganizationID string
	DepartmentID   string
}

// RateLimitExt contains rate limiting information
type RateLimitExt struct {
	Tier           string // "free", "basic", "premium", "enterprise"
	RequestsUsed   int64
	RequestsLimit  int64
	QuotaResetTime time.Time
	Throttled      bool
}

// TraceExt contains distributed tracing information
type TraceExt struct {
	TraceID       string
	SpanID        string
	ParentSpanID  string
	CorrelationID string
	OriginalUser  string // For delegation tracking
}

// ServiceMeshExt contains service mesh and infrastructure data
type ServiceMeshExt struct {
	ServiceName    string
	ServiceVersion string
	InstanceID     string
	Region         string
	Environment    string // "prod", "staging", "dev"
	MeshID         string
	TLSVersion     string
}

// NewExtensions creates a new Extensions instance with initialized custom map
func NewExtensions() *Extensions {
	return &Extensions{
		Custom: make(map[string]any),
	}
}

// WithSession adds session information to extensions
func (e *Extensions) WithSession(session *SessionExt) *Extensions {
	e.Session = session
	return e
}

// WithAuth adds authentication information to extensions
func (e *Extensions) WithAuth(auth *AuthExt) *Extensions {
	e.Auth = auth
	return e
}

// WithRateLimit adds rate limiting information to extensions
func (e *Extensions) WithRateLimit(rateLimit *RateLimitExt) *Extensions {
	e.RateLimit = rateLimit
	return e
}

// WithTrace adds tracing information to extensions
func (e *Extensions) WithTrace(trace *TraceExt) *Extensions {
	e.Trace = trace
	return e
}

// WithServiceMesh adds service mesh information to extensions
func (e *Extensions) WithServiceMesh(mesh *ServiceMeshExt) *Extensions {
	e.ServiceMesh = mesh
	return e
}

// WithCustom adds a custom extension value
func (e *Extensions) WithCustom(key string, value any) *Extensions {
	if e.Custom == nil {
		e.Custom = make(map[string]any)
	}
	e.Custom[key] = value
	return e
}

// Clone creates a deep copy of the extensions
func (e *Extensions) Clone() *Extensions {
	if e == nil {
		return nil
	}

	clone := &Extensions{
		Custom: make(map[string]any),
	}

	// Clone structured fields
	if e.Session != nil {
		session := *e.Session
		clone.Session = &session
	}

	if e.Auth != nil {
		auth := *e.Auth
		// Clone slices
		if e.Auth.Roles != nil {
			auth.Roles = append([]string(nil), e.Auth.Roles...)
		}
		if e.Auth.Groups != nil {
			auth.Groups = append([]string(nil), e.Auth.Groups...)
		}
		clone.Auth = &auth
	}

	if e.RateLimit != nil {
		rateLimit := *e.RateLimit
		clone.RateLimit = &rateLimit
	}

	if e.Trace != nil {
		trace := *e.Trace
		clone.Trace = &trace
	}

	if e.ServiceMesh != nil {
		mesh := *e.ServiceMesh
		clone.ServiceMesh = &mesh
	}

	// Clone custom map
	for k, v := range e.Custom {
		clone.Custom[k] = v
	}

	return clone
}