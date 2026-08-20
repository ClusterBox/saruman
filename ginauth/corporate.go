package ginauth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/clusterbox/saruman/cognito"
	"github.com/gin-gonic/gin"
)

// CorporateOptions configures per-service behavior of CorporateMiddleware. It is
// empty today and exists so a per-service hook (the corporate analogue of
// Options.OnTenantResolved) can be added later without breaking every consumer's
// call site.
type CorporateOptions struct{}

// CorporateMiddleware verifies the bearer token and resolves the caller's FULL
// set of administered businesses from the signed corpBusinessIds claim, for
// routes that summarize across a corporate rather than acting on one tenant.
//
// It deliberately does NOT set the tenant context key. MustGetTenantID therefore
// still panics on these routes, and that is load-bearing: it is the guardrail
// that stops a tenant-scoped handler from being mounted here and silently
// reading a zero tenant. A route needing one tenant wants Middleware, not this.
//
// Identity comes only from the verified claim. Unlike Middleware's
// AllowCorporateAdmin path — where an X-Business-Id header NARROWS a
// claim-granted set to one entry — nothing in the request selects, widens or
// filters the set exposed here.
func CorporateMiddleware(v cognito.Verifier, opts CorporateOptions) gin.HandlerFunc {
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

		// Distinct codes for absent vs malformed are safe here, unlike in
		// Middleware: these routes are corporate-only by their path, so there is
		// no "is this route corporate-enabled?" oracle to protect. Both answers
		// only describe the caller's own token, which they can already decode.
		businessIDs, err := claims.CorporateBusinessIDs()
		if err != nil {
			if errors.Is(err, cognito.ErrClaimMissing) {
				abort(c, http.StatusUnauthorized, "missing_corporate_claim",
					"token has no corporate businesses; this route is for corporate admins")
				return
			}
			slog.Warn("corpBusinessIds claim is present but unparseable", "error", err)
			abort(c, http.StatusUnauthorized, "invalid_corporate_claim",
				"corpBusinessIds claim is malformed")
			return
		}

		c.Set(corporateBusinessIDsKey, businessIDs)
		c.Next()
	}
}
