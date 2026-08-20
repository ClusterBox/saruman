package ginauth

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Context keys match the strings the services already use, so mixed-version
// deployments during migration read the same values.
const (
	tenantIDKey = "tenant_id"
	userIDKey   = "user_id"

	// permissionsKey memoizes the loaded permission set for one request, so a
	// route checking two permissions queries once.
	permissionsKey = "permissions"

	// permissionLoaderKey carries Options.PermissionLoader from Middleware to
	// RequirePermission, which runs as a separate per-route handler and so
	// cannot close over Options itself.
	permissionLoaderKey = "permission_loader"

	// corporateBusinessIDsKey carries the corporate admin's full administered
	// business set, set by CorporateMiddleware. Deliberately distinct from
	// tenantIDKey: a corporate-scoped route has no single tenant, and conflating
	// the two would let a tenant-scoped handler read something plausible-looking
	// on a route that never resolved one.
	corporateBusinessIDsKey = "corporate_business_ids"
)

// MustGetTenantID returns the verified tenant ID set by Middleware. Panics if
// called on a route the middleware does not protect (programming error).
func MustGetTenantID(c *gin.Context) uuid.UUID {
	val, exists := c.Get(tenantIDKey)
	if !exists {
		panic("MustGetTenantID called without ginauth.Middleware")
	}
	return val.(uuid.UUID)
}

// MustGetUserID returns the verified user ID. Panics if the middleware did
// not run or Options.RequireUserID was false.
func MustGetUserID(c *gin.Context) uuid.UUID {
	val, exists := c.Get(userIDKey)
	if !exists {
		panic("MustGetUserID called without ginauth.Middleware(RequireUserID)")
	}
	return val.(uuid.UUID)
}

// GetTenantID is the non-panicking form for handlers that already use the
// (value, ok) idiom.
func GetTenantID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(tenantIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := val.(uuid.UUID)
	return id, ok
}

// GetUserID is the non-panicking form of MustGetUserID.
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(userIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := val.(uuid.UUID)
	return id, ok
}

// MustGetCorporateBusinessIDs returns the verified business IDs set by
// CorporateMiddleware. Panics if called on a route that middleware does not
// protect (programming error).
func MustGetCorporateBusinessIDs(c *gin.Context) []uuid.UUID {
	val, exists := c.Get(corporateBusinessIDsKey)
	if !exists {
		panic("MustGetCorporateBusinessIDs called without ginauth.CorporateMiddleware")
	}
	return val.([]uuid.UUID)
}

// GetCorporateBusinessIDs is the non-panicking form of
// MustGetCorporateBusinessIDs.
func GetCorporateBusinessIDs(c *gin.Context) ([]uuid.UUID, bool) {
	val, exists := c.Get(corporateBusinessIDsKey)
	if !exists {
		return nil, false
	}
	ids, ok := val.([]uuid.UUID)
	return ids, ok
}
