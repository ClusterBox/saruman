package entitlements

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func countingLoader(e *Entitlements, calls *int32) Loader {
	return func(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error) {
		atomic.AddInt32(calls, 1)
		cp := *e
		return &cp, nil
	}
}

func TestResolve_CachesWithinTTL(t *testing.T) {
	var calls int32
	r := NewResolverWith(countingLoader(&Entitlements{PlanName: "Pro"}, &calls), nil, time.Minute)
	id := uuid.New()
	for i := 0; i < 2; i++ {
		if _, err := r.Resolve(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("want 1 load within TTL, got %d", calls)
	}
}

func TestResolve_ReloadsAfterTTL(t *testing.T) {
	var calls int32
	r := NewResolverWith(countingLoader(&Entitlements{}, &calls), nil, time.Millisecond)
	id := uuid.New()
	_, _ = r.Resolve(context.Background(), id)
	time.Sleep(5 * time.Millisecond)
	_, _ = r.Resolve(context.Background(), id)
	if calls != 2 {
		t.Fatalf("want reload after TTL, got %d loads", calls)
	}
}

func TestResolveFresh_BypassesCache(t *testing.T) {
	var calls int32
	r := NewResolverWith(countingLoader(&Entitlements{}, &calls), nil, time.Minute)
	id := uuid.New()
	_, _ = r.Resolve(context.Background(), id)
	_, _ = r.ResolveFresh(context.Background(), id)
	if calls != 2 {
		t.Fatalf("ResolveFresh must hit the loader, got %d loads", calls)
	}
}

func TestResolve_DoesNotCacheErrors(t *testing.T) {
	var calls int32
	r := NewResolverWith(func(ctx context.Context, id uuid.UUID) (*Entitlements, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("db down")
	}, nil, time.Minute)
	id := uuid.New()
	_, _ = r.Resolve(context.Background(), id)
	_, _ = r.Resolve(context.Background(), id)
	if calls != 2 {
		t.Fatalf("errors must not be cached, got %d loads", calls)
	}
}

func TestHas(t *testing.T) {
	e := &Entitlements{Features: []string{FeatureInvoices}}
	if !e.Has(FeatureInvoices) || e.Has(FeatureStaffManagement) {
		t.Fatal("Has mismatch")
	}
}

func TestAllFeatures_HasNoMeteredKey(t *testing.T) {
	for _, f := range AllFeatures {
		if f == "monthly_active_contacts" {
			t.Fatal("monthly_active_contacts is metered, not a feature key")
		}
	}
	if len(AllFeatures) != 26 {
		t.Fatalf("want 26 feature keys mirroring PlanFeatures, got %d", len(AllFeatures))
	}
}
