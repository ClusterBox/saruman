// Package ginauth is the gin glue over saruman's cognito verifier: one shared
// middleware for all Clusterbox Go services, with per-service policy injected
// via Options.
package ginauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/clusterbox/saruman/cognito"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthError is a hook-returnable error the middleware maps to an HTTP
// response with the standard {"error","message"} body.
type AuthError struct {
	Status  int
	Code    string
	Message string
}

func (e *AuthError) Error() string { return e.Code + ": " + e.Message }

// Sentinels a tenant-status hook returns. The bodies match the services'
// historical responses byte-for-byte; clients observe no change.
var (
	ErrTenantNotFound  = &AuthError{http.StatusUnauthorized, "invalid_tenant", "tenant not found"}
	ErrTenantSuspended = &AuthError{http.StatusForbidden, "account_suspended", "this account has been suspended"}
	ErrTenantLocked    = &AuthError{http.StatusForbidden, "account_locked", "this account is locked"}
	ErrTenantInactive  = &AuthError{http.StatusForbidden, "account_inactive", "this account is not active"}

	// ErrForbiddenTenant is the 403 a corporate admin receives when
	// X-Business-Id names a business not in their signed corpBusinessIds claim.
	ErrForbiddenTenant = &AuthError{http.StatusForbidden, "forbidden_tenant", "you do not have access to this business"}
)

// Options configures per-service behavior of Middleware.
type Options struct {
	// OnTenantResolved, if non-nil, runs after the tenant claim is verified.
	// Return nil to allow; an *AuthError for a mapped HTTP response; any
	// other error for a logged 500 — a DB outage must not read as an auth
	// failure.
	OnTenantResolved func(ctx context.Context, tenantID uuid.UUID) error

	// RequireUserID gates the userId claim. When false (default) the
	// middleware neither requires nor reads it. Flip to true only after the
	// pre-token Lambda stamps userId.
	RequireUserID bool

	// PermissionLoader resolves the caller's permissions for RequirePermission.
	// Leave nil unless a route uses RequirePermission — that middleware panics
	// rather than allowing a request through when the loader is missing.
	PermissionLoader PermissionLoader

	// AllowCorporateAdmin, if true, lets a caller with no tenantId claim but a
	// corpBusinessIds claim act on one of those businesses via the
	// X-Business-Id header, checked against that signed claim before being
	// trusted. Default false — every route's behavior is unchanged unless a
	// service opts in explicitly. A token carrying BOTH a tenantId and a
	// corpBusinessIds claim always resolves via tenantId — the header is never
	// read in that case.
	AllowCorporateAdmin bool
}

// Middleware verifies the bearer token and derives identity ONLY from
// verified claims — never trusts a header, body, query, or path param on its
// own. That is the property that closed the original cross-tenant IDOR and
// must be preserved. The one refinement: an opted-in route (see
// Options.AllowCorporateAdmin) may let the caller SELECT among tenants their
// own signed claim already grants — the header picks WHICH, the claim gates
// WHETHER, and it can never introduce a tenant the claim didn't already list.
func Middleware(v cognito.Verifier, opts Options) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := cognito.ExtractBearer(c.GetHeader("Authorization"))
		if raw == "" {
			abort(c, http.StatusUnauthorized, "missing_token",
				"Authorization: Bearer <access token> is required")
			return
		}

		claims, err := v.Verify(raw)
		if err != nil {
			abort(c, http.StatusUnauthorized, "invalid_token",
				"access token is invalid or expired")
			return
		}

		tenantID, err := claims.TenantID()
		if err != nil {
			if !errors.Is(err, cognito.ErrClaimMissing) {
				abort(c, http.StatusUnauthorized, "invalid_tenant_claim",
					"tenantId claim is not a valid UUID")
				return
			}
			if !opts.AllowCorporateAdmin {
				abort(c, http.StatusUnauthorized, "missing_tenant_claim",
					"token has no tenant; complete business setup first")
				return
			}

			businessIDs, bizErr := claims.CorporateBusinessIDs()
			if bizErr != nil {
				if !errors.Is(bizErr, cognito.ErrClaimMissing) {
					slog.Warn("corpBusinessIds claim is present but unparseable", "error", bizErr)
				}
				abort(c, http.StatusUnauthorized, "missing_tenant_claim",
					"token has no tenant; complete business setup first")
				return
			}

			header := c.GetHeader("X-Business-Id")
			if header == "" {
				abort(c, http.StatusBadRequest, "missing_business_header",
					"X-Business-Id header is required")
				return
			}
			selected, parseErr := uuid.Parse(header)
			if parseErr != nil {
				abort(c, http.StatusBadRequest, "invalid_business_header",
					"X-Business-Id header is not a valid UUID")
				return
			}

			allowed := false
			for _, id := range businessIDs {
				if id == selected {
					allowed = true
					break
				}
			}
			if !allowed {
				abort(c, ErrForbiddenTenant.Status, ErrForbiddenTenant.Code, ErrForbiddenTenant.Message)
				return
			}

			tenantID = selected
		}

		var userID uuid.UUID
		if opts.RequireUserID {
			userID, err = claims.UserID()
			if err != nil {
				if errors.Is(err, cognito.ErrClaimMissing) {
					abort(c, http.StatusUnauthorized, "missing_user_claim",
						"token has no userId claim")
				} else {
					abort(c, http.StatusUnauthorized, "invalid_user_claim",
						"userId claim is not a valid UUID")
				}
				return
			}
		}

		if opts.OnTenantResolved != nil {
			if err := opts.OnTenantResolved(c.Request.Context(), tenantID); err != nil {
				var ae *AuthError
				if errors.As(err, &ae) {
					abort(c, ae.Status, ae.Code, ae.Message)
					return
				}
				slog.Error("failed to validate tenant", "tenant_id", tenantID, "error", err)
				abort(c, http.StatusInternalServerError, "internal_error",
					"failed to validate tenant")
				return
			}
		}

		c.Set(tenantIDKey, tenantID)
		if opts.RequireUserID {
			c.Set(userIDKey, userID)
		}
		c.Set(permissionLoaderKey, opts.PermissionLoader)
		c.Next()
	}
}

func abort(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": code, "message": message})
}
