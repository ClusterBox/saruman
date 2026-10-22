package entitlements

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Plan-limit error codes. Aragorn emits the same codes inside its nested
// envelope; clients map all three to the upgrade prompt.
const (
	CodePlanUpgradeRequired = "plan_upgrade_required"
	CodeContactLimitReached = "contact_limit_reached"
	CodeContactLocked       = "contact_locked"
)

// WritePlanUpgradeRequired aborts with 403 naming the feature and the plan that has it.
func WritePlanUpgradeRequired(c *gin.Context, feature, requiredPlan string) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":        CodePlanUpgradeRequired,
		"message":      fmt.Sprintf("This feature is available on %s. Upgrade to use it.", requiredPlan),
		"feature":      feature,
		"requiredPlan": requiredPlan,
	})
}

// WriteContactLimitReached aborts with 403 when a user-initiated action would
// create a contact beyond the month's allowance.
func WriteContactLimitReached(c *gin.Context, limit, used int, periodEndsAt time.Time) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":        CodeContactLimitReached,
		"message":      fmt.Sprintf("You've reached your %d new contacts for this month.", limit),
		"limit":        limit,
		"used":         used,
		"periodEndsAt": periodEndsAt.UTC().Format(time.RFC3339),
	})
}

// WriteContactLocked aborts with 403 for any action on a locked contact.
func WriteContactLocked(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   CodeContactLocked,
		"message": "This customer is waiting for an upgrade.",
	})
}
