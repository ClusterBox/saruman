package ginauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clusterbox/saruman/cognito"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// stubVerifier returns canned claims without a live JWKS.
type stubVerifier struct {
	claims jwt.MapClaims
	err    error
}

func (s *stubVerifier) Verify(raw string) (*cognito.Claims, error) {
	if s.err != nil {
		return nil, s.err
	}
	return cognito.NewClaimsForTest(s.claims), nil
}

func serve(t *testing.T, v cognito.Verifier, opts Options, header string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware(v, opts))
	if handler == nil {
		handler = func(c *gin.Context) { c.Status(http.StatusOK) }
	}
	r.GET("/x", handler)
	req := httptest.NewRequest("GET", "/x", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not the {error,message} shape: %v", w.Body.String(), err)
	}
	if body.Message == "" {
		t.Fatalf("body %q has empty message", w.Body.String())
	}
	return body.Error
}

func TestMiddleware_Rejects(t *testing.T) {
	tid := uuid.New().String()
	cases := []struct {
		name     string
		header   string
		v        cognito.Verifier
		opts     Options
		wantCode int
		wantErr  string
	}{
		{"no authorization header", "", &stubVerifier{}, Options{}, 401, "missing_token"},
		{"malformed header", "NotBearer x", &stubVerifier{}, Options{}, 401, "missing_token"},
		{"invalid token", "Bearer bad", &stubVerifier{err: errors.New("boom")}, Options{}, 401, "invalid_token"},
		{"no tenantId claim", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"sub": "u1"}}, Options{}, 401, "missing_tenant_claim"},
		{"tenantId not a uuid", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"tenantId": "nope"}}, Options{}, 401, "invalid_tenant_claim"},
		{"RequireUserID missing claim", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"tenantId": tid}}, Options{RequireUserID: true}, 401, "missing_user_claim"},
		{"RequireUserID bad claim", "Bearer ok", &stubVerifier{claims: jwt.MapClaims{"tenantId": tid, "userId": "nope"}}, Options{RequireUserID: true}, 401, "invalid_user_claim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serve(t, tc.v, tc.opts, tc.header, nil)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if got := errCode(t, w); got != tc.wantErr {
				t.Fatalf("error code = %q, want %q", got, tc.wantErr)
			}
		})
	}
}

func TestMiddleware_TenantHook(t *testing.T) {
	tid := uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{"tenantId": tid.String()}}

	cases := []struct {
		name     string
		hookErr  error
		wantCode int
		wantErr  string
	}{
		{"nil hook error allows", nil, 200, ""},
		{"tenant not found", ErrTenantNotFound, 401, "invalid_tenant"},
		{"suspended", ErrTenantSuspended, 403, "account_suspended"},
		{"locked", ErrTenantLocked, 403, "account_locked"},
		{"inactive", ErrTenantInactive, 403, "account_inactive"},
		{"raw error is a 500, not an auth failure", errors.New("db down"), 500, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotTenant uuid.UUID
			opts := Options{OnTenantResolved: func(ctx context.Context, id uuid.UUID) error {
				gotTenant = id
				return tc.hookErr
			}}
			w := serve(t, v, opts, "Bearer ok", nil)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if gotTenant != tid {
				t.Fatalf("hook saw tenant %s, want %s", gotTenant, tid)
			}
			if tc.wantErr != "" {
				if got := errCode(t, w); got != tc.wantErr {
					t.Fatalf("error code = %q, want %q", got, tc.wantErr)
				}
			}
		})
	}
}

// THE REGRESSION TEST FOR THE ORIGINAL VULNERABILITY: identity comes only from
// the verified claim; forged X-Tenant-ID (or query param) is ignored.
func TestMiddleware_IgnoresForgedTenantHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	realTenant := uuid.New()
	victimTenant := uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{"tenantId": realTenant.String()}}

	r := gin.New()
	r.Use(Middleware(v, Options{}))
	r.GET("/x", func(c *gin.Context) {
		got := MustGetTenantID(c)
		if got == victimTenant {
			t.Fatal("SECURITY: forged X-Tenant-ID header was trusted")
		}
		if got != realTenant {
			t.Fatalf("want claim tenant %s, got %s", realTenant, got)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/x?tenant_id="+victimTenant.String(), nil)
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Tenant-ID", victimTenant.String()) // forged
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestMiddleware_HappyPathSetsContext(t *testing.T) {
	tid, uid := uuid.New(), uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{"tenantId": tid.String(), "userId": uid.String()}}

	w := serve(t, v, Options{RequireUserID: true}, "Bearer ok", func(c *gin.Context) {
		if MustGetTenantID(c) != tid {
			t.Error("tenant mismatch")
		}
		if MustGetUserID(c) != uid {
			t.Error("user mismatch")
		}
		if got, ok := GetTenantID(c); !ok || got != tid {
			t.Error("GetTenantID mismatch")
		}
		if got, ok := GetUserID(c); !ok || got != uid {
			t.Error("GetUserID mismatch")
		}
		c.Status(http.StatusOK)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestMiddleware_UserIDNotRequiredByDefault(t *testing.T) {
	tid := uuid.New()
	v := &stubVerifier{claims: jwt.MapClaims{"tenantId": tid.String()}} // no userId
	w := serve(t, v, Options{}, "Bearer ok", func(c *gin.Context) {
		if _, ok := GetUserID(c); ok {
			t.Error("user id must not be set when RequireUserID is false")
		}
		c.Status(http.StatusOK)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// serveCorporate builds a request with an Authorization header carrying the given
// claims and, when non-empty, an X-Business-Id header — for exercising the
// corporate-admin branch, which needs two headers where serve() only sets one.
func serveCorporate(t *testing.T, claims jwt.MapClaims, opts Options, businessHeader string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware(&stubVerifier{claims: claims}, opts))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer ok")
	if businessHeader != "" {
		req.Header.Set("X-Business-Id", businessHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestMiddleware_CorporateAdmin(t *testing.T) {
	a := uuid.New()
	b := uuid.New()
	corpClaims := jwt.MapClaims{"corpBusinessIds": a.String() + "," + b.String()}

	cases := []struct {
		name           string
		claims         jwt.MapClaims
		opts           Options
		businessHeader string
		wantCode       int
		wantErr        string // "" means 200 expected
	}{
		{
			name:     "AllowCorporateAdmin false: no tenantId still 401s exactly as today",
			claims:   corpClaims,
			opts:     Options{},
			wantCode: 401, wantErr: "missing_tenant_claim",
		},
		{
			name:     "AllowCorporateAdmin true, no corpBusinessIds claim either: 401 missing_tenant_claim",
			claims:   jwt.MapClaims{"sub": "u1"},
			opts:     Options{AllowCorporateAdmin: true},
			wantCode: 401, wantErr: "missing_tenant_claim",
		},
		{
			name:     "AllowCorporateAdmin true, corpBusinessIds present, header missing: 400",
			claims:   corpClaims,
			opts:     Options{AllowCorporateAdmin: true},
			wantCode: 400, wantErr: "missing_business_header",
		},
		{
			name:           "AllowCorporateAdmin true, header not a uuid: 400",
			claims:         corpClaims,
			opts:           Options{AllowCorporateAdmin: true},
			businessHeader: "not-a-uuid",
			wantCode:       400, wantErr: "invalid_business_header",
		},
		{
			name:           "AllowCorporateAdmin true, header valid uuid but not in claim list: 403",
			claims:         corpClaims,
			opts:           Options{AllowCorporateAdmin: true},
			businessHeader: uuid.New().String(),
			wantCode:       403, wantErr: "forbidden_tenant",
		},
		{
			name:           "AllowCorporateAdmin true, header valid uuid in claim list: 200",
			claims:         corpClaims,
			opts:           Options{AllowCorporateAdmin: true},
			businessHeader: b.String(),
			wantCode:       200, wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveCorporate(t, tc.claims, tc.opts, tc.businessHeader)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantErr != "" {
				if got := errCode(t, w); got != tc.wantErr {
					t.Fatalf("error code = %q, want %q", got, tc.wantErr)
				}
			}
		})
	}
}

// Regression: a caller with a VALID tenantId claim must not be affected by
// AllowCorporateAdmin or X-Business-Id in any way — the header must be read
// only when TenantID() itself came back ErrClaimMissing.
func TestMiddleware_CorporateAdmin_IgnoredWhenTenantClaimPresent(t *testing.T) {
	realTenant := uuid.New()
	otherBusiness := uuid.New()

	w := serveCorporate(t,
		jwt.MapClaims{"tenantId": realTenant.String()},
		Options{AllowCorporateAdmin: true},
		otherBusiness.String(),
	)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestMiddleware_CorporateAdmin_SetsSameContextKeyAsNormalPath(t *testing.T) {
	a := uuid.New()
	b := uuid.New()
	claims := jwt.MapClaims{"corpBusinessIds": a.String() + "," + b.String()}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware(&stubVerifier{claims: claims}, Options{AllowCorporateAdmin: true}))
	r.GET("/x", func(c *gin.Context) {
		if MustGetTenantID(c) != b {
			t.Error("tenant context was not set to the selected business")
		}
		if got, ok := GetTenantID(c); !ok || got != b {
			t.Error("GetTenantID mismatch")
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer ok")
	req.Header.Set("X-Business-Id", b.String())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestGetters_OutsideMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if _, ok := GetTenantID(c); ok {
		t.Fatal("GetTenantID must report absent")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustGetTenantID must panic without middleware")
		}
	}()
	MustGetTenantID(c)
}
