package ginauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// servePerm builds a router with Middleware + RequirePermission and returns the
// response. loader is installed via Options, mirroring real wiring.
func servePerm(t *testing.T, loader PermissionLoader, required []string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	v := &stubVerifier{claims: jwt.MapClaims{
		"tenantId": uuid.New().String(),
		"userId":   uuid.New().String(),
	}}

	r := gin.New()
	r.Use(Middleware(v, Options{RequireUserID: true, PermissionLoader: loader}))
	if handler == nil {
		handler = func(c *gin.Context) { c.Status(http.StatusOK) }
	}
	r.GET("/x", RequirePermission(required...), handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func staticLoader(perms ...string) PermissionLoader {
	return func(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
		return perms, nil
	}
}

func TestRequirePermission_Allows(t *testing.T) {
	w := servePerm(t, staticLoader("billing:read", "billing:manage"), []string{"billing:manage"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestRequirePermission_DeniesWhenMissing(t *testing.T) {
	w := servePerm(t, staticLoader("billing:read"), []string{"billing:manage"}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if got := errCode(t, w); got != "forbidden_permission" {
		t.Errorf("error code = %q, want forbidden_permission", got)
	}
}

// AND semantics, matching Aragorn's PermissionsGuard.
func TestRequirePermission_RequiresAll(t *testing.T) {
	w := servePerm(t, staticLoader("billing:read"), []string{"billing:read", "billing:manage"}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 when only one of two is held, got %d", w.Code)
	}
}

// A database outage must not read to a client as an authorization denial.
func TestRequirePermission_LoaderErrorIs500(t *testing.T) {
	loader := func(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
		return nil, errors.New("connection refused")
	}
	w := servePerm(t, loader, []string{"billing:manage"}, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on loader failure, got %d", w.Code)
	}
	if got := errCode(t, w); got != "internal_error" {
		t.Errorf("error code = %q, want internal_error", got)
	}
}

func TestRequirePermission_LoadsOncePerRequest(t *testing.T) {
	calls := 0
	loader := func(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
		calls++
		return []string{"a:read", "b:read"}, nil
	}

	gin.SetMode(gin.TestMode)
	v := &stubVerifier{claims: jwt.MapClaims{
		"tenantId": uuid.New().String(),
		"userId":   uuid.New().String(),
	}}
	r := gin.New()
	r.Use(Middleware(v, Options{RequireUserID: true, PermissionLoader: loader}))
	r.GET("/x",
		RequirePermission("a:read"),
		RequirePermission("b:read"),
		func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if calls != 1 {
		t.Errorf("loader called %d times, want 1 (must memoize per request)", calls)
	}
}

func TestGetPermissions_ExposesMemoizedSet(t *testing.T) {
	var got []string
	var ok bool
	w := servePerm(t, staticLoader("billing:read"), []string{"billing:read"}, func(c *gin.Context) {
		got, ok = GetPermissions(c)
		c.Status(http.StatusOK)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !ok || len(got) != 1 || got[0] != "billing:read" {
		t.Errorf("GetPermissions() = %v, %v; want [billing:read], true", got, ok)
	}
}

// A misconfigured loader must fail loudly at request time, never silently allow.
func TestRequirePermission_PanicsWithoutLoader(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic when Options.PermissionLoader is nil, got none")
		}
	}()

	gin.SetMode(gin.TestMode)
	v := &stubVerifier{claims: jwt.MapClaims{
		"tenantId": uuid.New().String(),
		"userId":   uuid.New().String(),
	}}
	r := gin.New()
	r.Use(Middleware(v, Options{RequireUserID: true}))
	r.GET("/x", RequirePermission("billing:read"), func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer token")
	r.ServeHTTP(httptest.NewRecorder(), req)
}

func TestRequirePermission_PanicsWithoutMiddleware(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic when Middleware did not run, got none")
		}
	}()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", RequirePermission("billing:read"), func(c *gin.Context) { c.Status(200) })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
}

func TestRequirePermission_PanicsWithNoPermissionsListed(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic when no permission is listed, got none")
		}
	}()
	RequirePermission()
}
