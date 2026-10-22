package entitlements

import (
	"log/slog"
	"net/http"

	"github.com/clusterbox/saruman/ginauth"
	"github.com/gin-gonic/gin"
)

// RequireFeature refuses the request with plan_upgrade_required unless the
// tenant's plan includes feature. Mount it after ginauth.Middleware: the tenant
// comes only from verified claims, never from a header.
//
// Never mount it on a corporate-scoped route (ginauth.CorporateMiddleware sets
// no tenant): it answers 500 there, loudly, rather than guessing a branch.
func RequireFeature(r *Resolver, feature string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := ginauth.GetTenantID(c)
		if !ok {
			slog.Error("entitlements.RequireFeature mounted on a route with no tenant in context (corporate route?)",
				"feature", feature, "path", c.FullPath())
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "message": "entitlements unavailable"})
			return
		}
		e, err := r.Resolve(c.Request.Context(), tenantID)
		if err != nil {
			slog.Error("failed to resolve entitlements", "tenant", tenantID, "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "message": "failed to resolve entitlements"})
			return
		}
		if !e.Has(feature) {
			WritePlanUpgradeRequired(c, feature, r.RequiredPlanFor(c.Request.Context(), feature))
			return
		}
		c.Next()
	}
}
