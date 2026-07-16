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
