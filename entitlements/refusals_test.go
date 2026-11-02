package entitlements

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type refusalLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *refusalLog) recorder() RefusalRecorder {
	return func(_ context.Context, tenantID uuid.UUID, feature string) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.seen = append(l.seen, tenantID.String()+"|"+feature)
	}
}

func TestRequireFeature_CountsRefusalsOnly(t *testing.T) {
	allowed, refused := uuid.New(), uuid.New()
	r := resolverFor(map[uuid.UUID][]string{allowed: {FeatureInvoices}, refused: {}})
	log := &refusalLog{}
	r.SetRefusalRecorder(log.recorder())

	if w := serve(t, r, withTenant(allowed), FeatureInvoices, nil); w.Code != http.StatusOK {
		t.Fatalf("allowed: %d", w.Code)
	}
	if w := serve(t, r, withTenant(refused), FeatureInvoices, nil); w.Code != http.StatusForbidden {
		t.Fatalf("refused: %d", w.Code)
	}
	if len(log.seen) != 1 || log.seen[0] != refused.String()+"|"+FeatureInvoices {
		t.Fatalf("recorded %v, want only the refusal", log.seen)
	}
}

func TestRecordRefusal_IsANoOpWithoutARecorder(t *testing.T) {
	var nilResolver *Resolver
	nilResolver.RecordRefusal(context.Background(), uuid.New(), FeatureInvoices)
	resolverFor(nil).RecordRefusal(context.Background(), uuid.New(), FeatureInvoices)
}

// Against a database with Aragorn's migrations; skipped without one.
func TestSQLRefusalRecorder_CountsPerTenantFeatureAndDay(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tenant := uuid.New()
	if _, err := db.Exec(`INSERT INTO tenants (id, business_name, slug, email) VALUES ($1, 'B', $2, 'b@x.co')`,
		tenant, "s-"+tenant.String()); err != nil {
		t.Fatal(err)
	}

	rec := SQLRefusalRecorder(db)
	for range 3 {
		rec(context.Background(), tenant, FeatureInvoices)
	}
	rec(context.Background(), tenant, FeatureServicesCatalog)

	// The writes run in the background; wait for them to land.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var invoices, services int
		_ = db.QueryRow(`SELECT COALESCE(SUM(count) FILTER (WHERE feature = $2), 0),
				COALESCE(SUM(count) FILTER (WHERE feature = $3), 0)
			FROM plan_refusals WHERE tenant_id = $1`, tenant, FeatureInvoices, FeatureServicesCatalog).Scan(&invoices, &services)
		if invoices == 3 && services == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counts = invoices %d, services %d; want 3 and 1", invoices, services)
		}
		time.Sleep(20 * time.Millisecond)
	}

	var rows int
	_ = db.QueryRow(`SELECT count(*) FROM plan_refusals WHERE tenant_id = $1`, tenant).Scan(&rows)
	if rows != 2 {
		t.Fatalf("%d rows, want one per feature for today", rows)
	}
}
