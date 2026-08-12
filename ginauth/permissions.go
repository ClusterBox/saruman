package ginauth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ErrForbiddenPermission is the 403 a caller receives when they hold a valid
// token for an active tenant but lack the permission a route requires. It
// matches the code Aragorn's PermissionsGuard emits, so one client branch
// handles both halves of the fleet.
var ErrForbiddenPermission = &AuthError{
	http.StatusForbidden, "forbidden_permission",
	"you do not have the required permissions to access this resource",
}

// PermissionLoader resolves the permission set for a verified user as
// "resource:action" strings. The service supplies it, so this package stays
// free of any database dependency — the same shape as Options.OnTenantResolved.
//
// tenantID is passed even though a caller may not need it: widening this
// signature later would break every consumer of the shared library.
type PermissionLoader func(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error)

// RequirePermission gates a route on the caller holding ALL of the listed
// permissions, matching the AND semantics of Aragorn's PermissionsGuard.
//
// It is a PER-ROUTE middleware, deliberately not part of Middleware's chain:
// attaching it globally would make every unprotected route pay for a query it
// never uses. The permission set is resolved lazily on first use and memoized
// for the rest of the request.
func RequirePermission(required ...string) gin.HandlerFunc {
	if len(required) == 0 {
		panic("ginauth.RequirePermission needs at least one permission")
	}

	return func(c *gin.Context) {
		perms, err := loadPermissions(c)
		if err != nil {
			// Never 403 here. A database outage is our failure, and answering
			// "forbidden" would tell a legitimate admin they lost access.
			slog.Error("failed to load permissions", "error", err)
			abort(c, http.StatusInternalServerError, "internal_error", "failed to load permissions")
			return
		}

		held := make(map[string]struct{}, len(perms))
		for _, p := range perms {
			held[p] = struct{}{}
		}

		for _, want := range required {
			if _, ok := held[want]; !ok {
				abort(c, ErrForbiddenPermission.Status, ErrForbiddenPermission.Code,
					ErrForbiddenPermission.Message)
				return
			}
		}

		c.Next()
	}
}

// GetPermissions returns the memoized permission set for handlers that need
// conditional behavior rather than a hard gate. Only populated once a
// RequirePermission check has run on the route.
func GetPermissions(c *gin.Context) ([]string, bool) {
	val, exists := c.Get(permissionsKey)
	if !exists {
		return nil, false
	}
	perms, ok := val.([]string)
	return perms, ok
}

// loadPermissions resolves the caller's permissions once per request.
//
// Every failure below is a programming error — a route wired without the
// middleware or without a loader — so each panics rather than returning an
// error a caller might mistake for "deny". Silently allowing here would be the
// worst outcome: the gate would appear installed and enforce nothing.
func loadPermissions(c *gin.Context) ([]string, error) {
	if cached, exists := c.Get(permissionsKey); exists {
		perms, _ := cached.([]string)
		return perms, nil
	}

	raw, exists := c.Get(permissionLoaderKey)
	if !exists {
		panic("ginauth.RequirePermission used on a route without ginauth.Middleware")
	}
	loader, _ := raw.(PermissionLoader)
	if loader == nil {
		panic("ginauth.RequirePermission requires Options.PermissionLoader to be set")
	}

	tenantID, ok := GetTenantID(c)
	if !ok {
		panic("ginauth.RequirePermission used on a route without ginauth.Middleware")
	}
	userID, ok := GetUserID(c)
	if !ok {
		panic("ginauth.RequirePermission requires Options.RequireUserID")
	}

	perms, err := loader(c.Request.Context(), tenantID, userID)
	if err != nil {
		return nil, err
	}

	c.Set(permissionsKey, perms)
	return perms, nil
}
