package entitlements

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// RefusalRecorder notes that a tenant was refused a feature its plan lacks.
// It must not block: it runs on the request path of every refusal.
type RefusalRecorder func(ctx context.Context, tenantID uuid.UUID, feature string)

// Execer is the subset of *sql.DB / *sqlx.DB a recorder needs.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// refusalTimeout bounds one background count.
const refusalTimeout = 3 * time.Second

// SQLRefusalRecorder counts refusals in Aragorn's plan_refusals table, one
// row per (tenant, feature, UTC day). smaug's trial offer reads it to reach a
// workspace that keeps hitting the same locked feature. The write happens in
// the background, detached from the request, and a failure is only logged:
// counting must never change, slow or fail the refusal itself.
func SQLRefusalRecorder(db Execer) RefusalRecorder {
	return func(ctx context.Context, tenantID uuid.UUID, feature string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refusalTimeout)
		go func() {
			defer cancel()
			if err := recordRefusal(ctx, db, tenantID, feature); err != nil {
				slog.Warn("could not record plan refusal", "tenant", tenantID, "feature", feature, "error", err)
			}
		}()
	}
}

// recordRefusal is the upsert, shared with Aragorn's EntitlementsService.
func recordRefusal(ctx context.Context, db Execer, tenantID uuid.UUID, feature string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO plan_refusals (tenant_id, feature, day, count, last_at)
		VALUES ($1, $2, (now() AT TIME ZONE 'UTC')::date, 1, now())
		ON CONFLICT (tenant_id, feature, day)
		DO UPDATE SET count = plan_refusals.count + 1, last_at = now()`,
		tenantID, feature)
	return err
}

// SetRefusalRecorder makes RequireFeature, and RecordRefusal, count every
// refusal. Without one nothing is counted.
func (r *Resolver) SetRefusalRecorder(rec RefusalRecorder) { r.onRefused = rec }

// RecordRefusal counts a refusal written outside RequireFeature, e.g. by a
// handler that gates on the request body. A no-op without a recorder.
func (r *Resolver) RecordRefusal(ctx context.Context, tenantID uuid.UUID, feature string) {
	if r != nil && r.onRefused != nil {
		r.onRefused(ctx, tenantID, feature)
	}
}
