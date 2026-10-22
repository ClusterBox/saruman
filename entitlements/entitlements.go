// Package entitlements answers "what is this tenant entitled to right now?"
// for the Go services, by reading the tenant_entitlements() SQL function that
// Aragorn's migrations own. Every service reads that one function, so a future
// trial or override changes all of them at once. Never derive entitlements from
// plan names or hard-coded tier lists.
package entitlements

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Entitlements mirrors one row of tenant_entitlements(). Nil limits are unlimited.
type Entitlements struct {
	PlanID         *uuid.UUID
	PlanName       string
	Features       []string
	MaxSeats       int
	MaxChannels    *int
	MaxNewContacts *int
	Source         string
}

// Has reports whether the tenant's plan includes feature.
func (e *Entitlements) Has(feature string) bool { return slices.Contains(e.Features, feature) }

// DB is the subset of *sql.DB / *sqlx.DB the resolver needs.
type DB interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Loader fetches a tenant's entitlements, uncached.
type Loader func(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error)

// PlanFinder names the cheapest live plan that includes a feature.
type PlanFinder func(ctx context.Context, feature string) (string, error)

type cached struct {
	value   *Entitlements
	expires time.Time
}

// Resolver caches entitlements per tenant for ttl. An upgrade can therefore
// take up to ttl to apply; keep ttl short (the services use 30s).
type Resolver struct {
	load     Loader
	findPlan PlanFinder
	ttl      time.Duration
	cache    sync.Map // uuid.UUID -> cached
}

// NewResolver reads tenant_entitlements() through db.
func NewResolver(db DB, ttl time.Duration) *Resolver {
	return NewResolverWith(SQLLoader(db), SQLPlanFinder(db), ttl)
}

// NewResolverWith builds a resolver over custom sources (tests, fakes).
func NewResolverWith(load Loader, findPlan PlanFinder, ttl time.Duration) *Resolver {
	return &Resolver{load: load, findPlan: findPlan, ttl: ttl}
}

// Resolve returns the tenant's entitlements, from cache when fresh.
func (r *Resolver) Resolve(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error) {
	if v, ok := r.cache.Load(tenantID); ok {
		if c := v.(cached); time.Now().Before(c.expires) {
			return c.value, nil
		}
	}
	return r.ResolveFresh(ctx, tenantID)
}

// ResolveFresh bypasses the cache (and refreshes it). Use it where acting on a
// stale answer is costly, e.g. deciding whether to unlock contacts.
func (r *Resolver) ResolveFresh(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error) {
	e, err := r.load(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	r.cache.Store(tenantID, cached{value: e, expires: time.Now().Add(r.ttl)})
	return e, nil
}

// RequiredPlanFor names the cheapest live plan that includes feature, for
// upgrade prompts. Falls back to "a paid plan" when none can be found.
func (r *Resolver) RequiredPlanFor(ctx context.Context, feature string) string {
	if r.findPlan == nil {
		return "a paid plan"
	}
	name, err := r.findPlan(ctx, feature)
	if err != nil || name == "" {
		return "a paid plan"
	}
	return name
}

// SQLLoader reads tenant_entitlements(). features is decoded via JSON so the
// loader works on any database/sql driver without array support.
func SQLLoader(db DB) Loader {
	return func(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error) {
		var (
			e        Entitlements
			planID   uuid.NullUUID
			planName sql.NullString
			features string
			channels sql.NullInt64
			contacts sql.NullInt64
		)
		err := db.QueryRowContext(ctx, `
			SELECT plan_id, plan_name, array_to_json(features)::text, max_seats, max_channels, max_new_contacts, source
			FROM tenant_entitlements($1)`, tenantID).
			Scan(&planID, &planName, &features, &e.MaxSeats, &channels, &contacts, &e.Source)
		if err != nil {
			return nil, fmt.Errorf("resolve entitlements for tenant %s: %w", tenantID, err)
		}
		if planID.Valid {
			e.PlanID = &planID.UUID
		}
		e.PlanName = planName.String
		if err := json.Unmarshal([]byte(features), &e.Features); err != nil {
			return nil, fmt.Errorf("decode features: %w", err)
		}
		e.MaxChannels = nullInt(channels)
		e.MaxNewContacts = nullInt(contacts)
		return &e, nil
	}
}

// SQLPlanFinder queries subscription_plans for the cheapest live plan with feature enabled.
func SQLPlanFinder(db DB) PlanFinder {
	return func(ctx context.Context, feature string) (string, error) {
		var name string
		err := db.QueryRowContext(ctx, `
			SELECT p.name FROM subscription_plans p
			WHERE NOT p.archived AND EXISTS (
				SELECT 1 FROM jsonb_array_elements(p.features) f
				WHERE f->>'key' = $1 AND COALESCE((f->>'enabled')::boolean, true)
			)
			ORDER BY p.price ASC LIMIT 1`, feature).Scan(&name)
		return name, err
	}
}

func nullInt(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}
