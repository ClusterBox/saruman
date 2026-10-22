package entitlements

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// withTenant stands in for ginauth.Middleware: it puts a verified tenant id
// under the same context key ginauth uses ("tenant_id").
func withTenant(id uuid.UUID) gin.HandlerFunc {
	return func(c *gin.Context) { c.Set("tenant_id", id); c.Next() }
}

func serve(t *testing.T, r *Resolver, pre gin.HandlerFunc, feature string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	e := gin.New()
	if pre != nil {
		e.Use(pre)
	}
	e.GET("/x", RequireFeature(r, feature), func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest("GET", "/x", nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w
}

func resolverFor(byTenant map[uuid.UUID][]string) *Resolver {
	return NewResolverWith(
		func(ctx context.Context, id uuid.UUID) (*Entitlements, error) {
			return &Entitlements{Features: byTenant[id]}, nil
		},
		func(ctx context.Context, feature string) (string, error) { return "Pro", nil },
		time.Minute,
	)
}

func TestRequireFeature_PassesWhenPresent(t *testing.T) {
	id := uuid.New()
	w := serve(t, resolverFor(map[uuid.UUID][]string{id: {FeatureInvoices}}), withTenant(id), FeatureInvoices, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestRequireFeature_RefusesWithPlanUpgradeRequired(t *testing.T) {
	id := uuid.New()
	w := serve(t, resolverFor(map[uuid.UUID][]string{id: {}}), withTenant(id), FeatureInvoices, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "plan_upgrade_required" || body["feature"] != "invoices" || body["requiredPlan"] != "Pro" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestRequireFeature_NoTenantIs500(t *testing.T) {
	w := serve(t, resolverFor(nil), nil, FeatureInvoices, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when mounted without a tenant, got %d", w.Code)
	}
}

func TestRequireFeature_IgnoresTenantHeader(t *testing.T) {
	real, forged := uuid.New(), uuid.New()
	r := resolverFor(map[uuid.UUID][]string{real: {}, forged: {FeatureInvoices}})
	w := serve(t, r, withTenant(real), FeatureInvoices, map[string]string{"X-Tenant-ID": forged.String()})
	if w.Code != http.StatusForbidden {
		t.Fatalf("forged X-Tenant-ID must not grant the feature, got %d", w.Code)
	}
}

func TestWriteContactLimitReached(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	WriteContactLimitReached(c, 25, 25, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 403 || body["error"] != "contact_limit_reached" || body["limit"] != float64(25) ||
		body["used"] != float64(25) || body["periodEndsAt"] != "2026-11-01T00:00:00Z" {
		t.Fatalf("unexpected: %d %v", w.Code, body)
	}
}

func TestWriteContactLocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	WriteContactLocked(c)
	if w.Code != 403 || !json.Valid(w.Body.Bytes()) || !strings.Contains(w.Body.String(), `"error":"contact_locked"`) {
		t.Fatalf("unexpected: %d %s", w.Code, w.Body.String())
	}
}
