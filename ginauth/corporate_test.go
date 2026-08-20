package ginauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clusterbox/saruman/cognito"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// serveCorporateScope runs one request through CorporateMiddleware. Mirrors
// serve() in middleware_test.go, which is bound to the tenant-scoped Middleware
// and so cannot be reused here.
func serveCorporateScope(t *testing.T, v cognito.Verifier, authHeader string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CorporateMiddleware(v, CorporateOptions{}))
	if handler == nil {
		handler = func(c *gin.Context) { c.Status(http.StatusOK) }
	}
	r.GET("/x", handler)

	req := httptest.NewRequest("GET", "/x", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCorporateMiddleware_Rejects(t *testing.T) {
	cases := []struct {
		name     string
		header   string
		v        cognito.Verifier
		wantCode int
		wantErr  string
	}{
		{"no authorization header", "", &stubVerifier{}, 401, "missing_token"},
		{"malformed header", "NotBearer x", &stubVerifier{}, 401, "missing_token"},
		{"invalid token", "Bearer bad", &stubVerifier{err: errors.New("boom")}, 401, "invalid_token"},
		{"no corpBusinessIds claim", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"sub": "u1"}}, 401, "missing_corporate_claim"},
		{"a tenantId claim alone does not qualify", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"tenantId": uuid.New().String()}}, 401, "missing_corporate_claim"},
		{"corpBusinessIds present but malformed", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"corpBusinessIds": "not-a-uuid"}}, 401, "invalid_corporate_claim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveCorporateScope(t, tc.v, tc.header, nil)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
			if got := errCode(t, w); got != tc.wantErr {
				t.Fatalf("error code = %q, want %q", got, tc.wantErr)
			}
		})
	}
}

func TestCorporateMiddleware_PopulatesContext(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{"corpBusinessIds": a.String() + "," + b.String()}}

	w := serveCorporateScope(t, v, "Bearer ok", func(c *gin.Context) {
		got := MustGetCorporateBusinessIDs(c)
		if len(got) != 2 || got[0] != a || got[1] != b {
			t.Errorf("MustGetCorporateBusinessIDs = %v, want [%s %s]", got, a, b)
		}
		ids, ok := GetCorporateBusinessIDs(c)
		if !ok || len(ids) != 2 {
			t.Errorf("GetCorporateBusinessIDs = (%v, %v), want 2 ids and true", ids, ok)
		}
		c.Status(http.StatusOK)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// THE GUARDRAIL. A corporate-scoped route has no single tenant, so MustGetTenantID
// must panic rather than hand a handler a zero UUID. This is what stops a
// tenant-scoped handler from later being mounted on a corporate route and
// silently serving the wrong tenant — or every tenant.
func TestCorporateMiddleware_DoesNotSetTenantID(t *testing.T) {
	a := uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{"corpBusinessIds": a.String()}}

	var tenantSet, panicked, rawSet bool

	w := serveCorporateScope(t, v, "Bearer ok", func(c *gin.Context) {
		_, tenantSet = GetTenantID(c)
		_, rawSet = c.Get(tenantIDKey)
		// Isolated so the recover cannot swallow an unrelated panic and so the
		// handler continues normally afterwards.
		func() {
			defer func() { panicked = recover() != nil }()
			MustGetTenantID(c)
		}()
		c.Status(http.StatusOK)
	})

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if tenantSet {
		t.Error("tenant_id must not be set on a corporate-scoped route")
	}
	if !panicked {
		t.Error("MustGetTenantID must panic on a corporate-scoped route")
	}
	if rawSet {
		t.Error("the raw tenant_id key must not be set on a corporate-scoped route")
	}
}

// A token carrying BOTH claims is a real shape — Aragorn's pre-token-generation
// Lambda is tested to emit tenantId, userId and corpBusinessIds together. On a
// corporate-scoped route the corporate set is what matters and tenantId is
// ignored: the mirror of the precedence Middleware enforces in the other
// direction.
func TestCorporateMiddleware_DualClaimUsesCorporateSet(t *testing.T) {
	tenant, a := uuid.New(), uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{
		"tenantId":        tenant.String(),
		"corpBusinessIds": a.String(),
	}}

	w := serveCorporateScope(t, v, "Bearer ok", func(c *gin.Context) {
		got := MustGetCorporateBusinessIDs(c)
		if len(got) != 1 || got[0] != a {
			t.Errorf("got %v, want [%s]", got, a)
		}
		if _, ok := GetTenantID(c); ok {
			t.Error("tenant_id must not be set even when the token carries a tenantId claim")
		}
		c.Status(http.StatusOK)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestGetCorporateBusinessIDs_OutsideMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if _, ok := GetCorporateBusinessIDs(c); ok {
		t.Fatal("GetCorporateBusinessIDs must report absent")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustGetCorporateBusinessIDs must panic without middleware")
		}
	}()
	MustGetCorporateBusinessIDs(c)
}
