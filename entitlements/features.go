package entitlements

// Plan feature keys. These mirror PlanFeatures in Aragorn
// (src/common/constants/plan-features.constants.ts), the seed of every plan's
// `features` JSON. Aragorn's saruman-drift.spec.ts fails if the lists diverge.
//
// monthly_active_contacts is deliberately absent: it is a metered entry, surfaced
// as Entitlements.MaxNewContacts, never a feature key.
const (
	FeatureUnifiedInbox             = "unified_inbox"
	FeatureAssignmentNotesMentions  = "assignment_notes_mentions"
	FeatureOrdersManual             = "orders_manual"
	FeatureBookingsSlotsConflicts   = "bookings_slots_conflicts"
	FeatureCalendar                 = "calendar"
	FeatureServicesCatalog          = "services_catalog"
	FeaturePaymentWorkflows         = "payment_workflows"
	FeaturePaymentPayLink           = "payment_pay_link"
	FeaturePaymentStkPrompt         = "payment_stk_prompt"
	FeaturePaymentMarkCash          = "payment_mark_cash"
	FeatureRefundsMinimal           = "refunds_minimal"
	FeatureInvoices                = "invoices"
	FeatureDeliveriesRiderLinks     = "deliveries_rider_links"
	FeatureCustomer360              = "customer_360"
	FeatureAutomatedStatusTemplates = "automated_status_templates"
	FeatureDashboardReports         = "dashboard_reports"
	FeatureAnalyticsByChannel       = "analytics_by_channel"
	FeatureMultiUserRoles           = "multi_user_roles"
	FeatureRoleOwner                = "role_owner"
	FeatureRoleManager              = "role_manager"
	FeatureRoleAgent                = "role_agent"
	FeaturePresenceSoftLock         = "presence_soft_lock"
	FeatureTeamAssignment           = "team_assignment"
	FeatureRolesBasic               = "roles_basic"
	FeatureStaffManagement          = "staff_management"
	FeaturePrioritySupport          = "priority_support"
)

// AllFeatures lists every key above, in declaration order.
var AllFeatures = []string{
	FeatureUnifiedInbox,
	FeatureAssignmentNotesMentions,
	FeatureOrdersManual,
	FeatureBookingsSlotsConflicts,
	FeatureCalendar,
	FeatureServicesCatalog,
	FeaturePaymentWorkflows,
	FeaturePaymentPayLink,
	FeaturePaymentStkPrompt,
	FeaturePaymentMarkCash,
	FeatureRefundsMinimal,
	FeatureInvoices,
	FeatureDeliveriesRiderLinks,
	FeatureCustomer360,
	FeatureAutomatedStatusTemplates,
	FeatureDashboardReports,
	FeatureAnalyticsByChannel,
	FeatureMultiUserRoles,
	FeatureRoleOwner,
	FeatureRoleManager,
	FeatureRoleAgent,
	FeaturePresenceSoftLock,
	FeatureTeamAssignment,
	FeatureRolesBasic,
	FeatureStaffManagement,
	FeaturePrioritySupport,
}
