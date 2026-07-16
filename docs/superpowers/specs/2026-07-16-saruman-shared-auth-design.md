# Saruman — Shared Cognito Auth for Clusterbox Go Services

**Date:** 2026-07-16
**Status:** Design approved, pending spec review
**Module:** `github.com/clusterbox/saruman`
**Repo:** `github.com/ClusterBox/saruman` (GitHub resolves org casing case-insensitively; module path is lowercase to match smaug's `github.com/clusterbox/smaug`)

## Problem

The Cognito access-token verifier is duplicated across the Go services. `CognitoVerifier`,
`NewVerifier`, `Verify`, and `bearerToken` are byte-for-byte identical in:

- `legolas/internal/middleware/auth.go`
- `smaug/internal/middleware/auth.go`
- (smaug defines the verifier a second time; its `tenant.go` middleware also depends on it)

`AuthMiddleware` and the `MustGetTenantID` helper are near-identical, differing only in that
smaug performs an additional tenant-status DB check (ACTIVE / SUSPENDED / LOCKED) while legolas
is token-only.

This duplication is a security liability: a fix to `Verify` (the function that decides whether a
token is trusted) only lands in whichever repo the author remembers to patch. The copies will
drift. This spec consolidates verification into one auditable module that both services import.

## Goals

- One auditable implementation of Cognito access-token verification for all Go services.
- A single gin middleware both services use, with the per-service DB status check injected as a hook.
- Typed claim accessors: `TenantID()`, `UserID()`, `Subject()` — so the deferred `authorId`-in-body
  forgery (internal notes) can be fixed by deriving the author from the token instead of the request body.
- No behavior change for clients: identical HTTP statuses and JSON error bodies.

## Non-Goals

- Changing the pre-token-generation Lambda. `UserID()` support is built but gated off (see
  `RequireUserID`) until the Lambda stamps a `userId` claim. Stamping that claim and applying the
  authorId fix is a **follow-up effort**, not this spec.
- Changing legolas's behavior (it stays token-only; it does not gain a DB status check).
- Any non-Go service. Aragorn (NestJS) is out of scope.

## Distribution

Public tagged Go module. Each service adds it to `go.mod` and `go get`s a tagged version.
Chosen over a private module (no `GOPRIVATE` / token plumbing needed in the Citadel Docker builds
or Lambda/ECS pipelines) and over a go.work/replace setup (services build from separate repos and
Docker contexts, so a monorepo-local path would break those builds).

```
// smaug/go.mod, legolas/go.mod
require github.com/clusterbox/saruman v0.1.0
```

## Module Layout

Two packages so callers pull in only what they need. The `cognito` package has **no gin and no DB
dependency**; the `ginauth` package is the web glue.

```
saruman/
├── go.mod                        // module github.com/clusterbox/saruman
├── cognito/                      // framework-agnostic. no gin, no db.
│   ├── verifier.go               // Verifier interface, CognitoVerifier, NewVerifier, Verify
│   ├── claims.go                 // Claims: TenantID(), UserID(), Subject()
│   ├── bearer.go                 // ExtractBearer(authHeader string) string
│   └── *_test.go
└── ginauth/                      // gin glue. imports cognito + gin.
    ├── middleware.go             // Middleware(v, Options) gin.HandlerFunc, AuthError, sentinels
    ├── context.go                // MustGetTenantID(c), MustGetUserID(c), context keys
    └── *_test.go
```

## Public API

### package `cognito`

```go
// Verifier validates a raw JWT and returns its claims. Interface so callers/tests
// can stub without a live JWKS endpoint.
type Verifier interface {
    Verify(raw string) (*Claims, error)
}

// CognitoVerifier verifies Cognito ACCESS tokens against the pool's JWKS.
type CognitoVerifier struct { /* keyfunc, issuer, clientID */ }

// NewVerifier builds a verifier with a CACHED, auto-refreshing JWKS.
func NewVerifier(ctx context.Context, region, poolID, clientID string) (*CognitoVerifier, error)

// Verify checks signature (RS256 only), issuer, expiry, token_use == "access",
// and client_id. Never panics; all failures are returned errors.
func (v *CognitoVerifier) Verify(raw string) (*Claims, error)

// Claims wraps the verified JWT claims with typed, validated accessors.
type Claims struct { /* wraps jwt.MapClaims */ }

func (c *Claims) TenantID() (uuid.UUID, error) // errors: missing, not-a-uuid
func (c *Claims) UserID()   (uuid.UUID, error) // errors: missing, not-a-uuid
func (c *Claims) Subject()  string             // cognito sub, present today

// ExtractBearer returns the token from an "Authorization: Bearer <t>" header value,
// or "" if absent/malformed. Framework-free.
func ExtractBearer(authHeader string) string
```

`Verify` retains today's exact checks: `jwt.WithValidMethods(["RS256"])` (blocks
algorithm-confusion incl. `alg=none` and HS256), `jwt.WithIssuer`, `jwt.WithExpirationRequired`,
`jwt.WithLeeway(30s)`, `token_use == "access"`, `client_id == v.clientID`. A validly signed **ID**
token is rejected because its `token_use` is not `access`.

### package `ginauth`

```go
type Options struct {
    // OnTenantResolved, if non-nil, runs after the tenant claim is verified.
    // Return nil to allow; return an *AuthError for a mapped HTTP response;
    // return any other error for 500 internal_error (logged). smaug passes its
    // tenant-status check; legolas leaves this nil.
    OnTenantResolved func(ctx context.Context, tenantID uuid.UUID) error

    // RequireUserID gates the userId claim. When false (default), the middleware
    // does not require or read userId — tokens without it pass. Flip to true only
    // after the pre-token Lambda stamps userId.
    RequireUserID bool
}

func Middleware(v cognito.Verifier, opts Options) gin.HandlerFunc

// AuthError is a hook-returnable error the middleware maps to an HTTP response.
type AuthError struct { Status int; Code, Message string }
func (e *AuthError) Error() string

// Sentinels smaug's status hook returns:
var (
    ErrTenantNotFound  = &AuthError{401, "invalid_tenant",    "tenant not found"}
    ErrTenantSuspended = &AuthError{403, "account_suspended", "this account has been suspended"}
    ErrTenantLocked    = &AuthError{403, "account_locked",    "this account is locked"}
    ErrTenantInactive  = &AuthError{403, "account_inactive",  "this account is not active"}
)

// Panicking getters (programming-error contract): use where the middleware is
// guaranteed to have run.
func MustGetTenantID(c *gin.Context) uuid.UUID
func MustGetUserID(c *gin.Context)   uuid.UUID

// Non-panicking getters — legolas already uses the (value, ok) form in some
// handlers; provided so those call sites port 1:1.
func GetTenantID(c *gin.Context) (uuid.UUID, bool)
func GetUserID(c *gin.Context)   (uuid.UUID, bool)
```

## Middleware Sequence

```
1. ExtractBearer(Authorization header)
     empty            → 401 {"error":"missing_token", ...}
2. v.Verify(raw)
     error            → 401 {"error":"invalid_token", ...}
3. claims.TenantID()
     missing          → 401 {"error":"missing_tenant_claim", ...}
     not-a-uuid       → 401 {"error":"invalid_tenant_claim", ...}
4. claims.UserID()   [only if opts.RequireUserID]
     missing          → 401 {"error":"missing_user_claim", ...}
     not-a-uuid       → 401 {"error":"invalid_user_claim", ...}
5. opts.OnTenantResolved(ctx, tenantID)   [skipped if nil]
     *AuthError       → that error's Status/Code/Message
     other error      → 500 {"error":"internal_error", ...} (logged via slog)
     nil              → allow
6. c.Set(tenant key, tenantID); c.Set(user key, userID if required); c.Next()
```

The tenant (and user) is read **only** from the verified claim — never from a header, body, query,
or path param. This is the property that closed the original cross-tenant IDOR and must be preserved.

JSON error bodies match today's shape exactly (`{"error": <code>, "message": <text>}`), so no
client observes a behavior change.

## Smaug's Tenant-Status Hook (stays in smaug)

The ACTIVE/SUSPENDED/LOCKED switch is smaug's domain logic and remains in the smaug repo. It becomes
a small constructor returning an `OnTenantResolved` func:

```go
func smaugTenantStatus(db *sqlx.DB) func(context.Context, uuid.UUID) error {
    return func(ctx context.Context, tid uuid.UUID) error {
        ctx, cancel := context.WithTimeout(ctx, 10*time.Second); defer cancel()
        var row struct { Status string; DeletedAt sql.NullTime }
        err := db.GetContext(ctx, &row, `SELECT status, deleted_at FROM tenants WHERE id=$1`, tid)
        switch {
        case err == sql.ErrNoRows || (err == nil && row.DeletedAt.Valid):
            return ginauth.ErrTenantNotFound
        case err != nil:
            return fmt.Errorf("validate tenant %s: %w", tid, err) // → 500
        }
        switch row.Status {
        case "ACTIVE", "GRACE_PERIOD": return nil
        case "SUSPENDED":              return ginauth.ErrTenantSuspended
        case "LOCKED":                 return ginauth.ErrTenantLocked
        default:                       return ginauth.ErrTenantInactive
        }
    }
}
```

A soft-deleted tenant (`deleted_at` set) returns `ErrTenantNotFound` (a 401 "tenant not found"),
matching today's behavior of not leaking existence. A real DB error returns a wrapped non-`AuthError`
so the middleware answers 500, not 401 — a DB outage must not read as an auth failure.

## Migration

Saruman ships first (`v0.1.0`), then each service adopts it in a **separate PR on its `development`
branch** (same pattern as the JWT-tenant-claim rollout).

### Smaug (`github.com/clusterbox/smaug`)
- `go get github.com/clusterbox/saruman@v0.1.0`
- **Delete** `internal/middleware/auth.go`; strip the verifier + middleware bulk from
  `internal/middleware/tenant.go`, leaving only `smaugTenantStatus`.
- `main.go`: `middleware.NewVerifier(...)` → `cognito.NewVerifier(...)`.
- `router.go`: `middleware.AuthMiddleware(r.verifier, r.db)` →
  `ginauth.Middleware(verifier, ginauth.Options{OnTenantResolved: smaugTenantStatus(db)})`.
- `MustGetTenantID` call sites → `ginauth.MustGetTenantID`.
- `RequireUserID` stays **false**.

### Legolas (`github.com/ClusterBox/legolas.git`)
- `go get github.com/clusterbox/saruman@v0.1.0`
- **Delete** `internal/middleware/auth.go`; strip tenant helpers from `internal/middleware/tenant.go`.
- `main.go`: verifier construction → `cognito.NewVerifier`.
- `router.go`: both `AuthMiddleware` call sites (including `/ws`) →
  `ginauth.Middleware(verifier, ginauth.Options{})` (no hook).
- `MustGetTenantID` and `GetTenantID` call sites → `ginauth.MustGetTenantID` / `ginauth.GetTenantID`.
- `RequireUserID` stays **false**.

### Follow-up (out of scope here)
Once the pre-token-generation Lambda stamps a `userId` claim (parallel to `tenantId`, via a
`custom:userId` attribute), flip `RequireUserID` on and replace the internal-notes `authorId`-in-body
with `ginauth.MustGetUserID(c)`. Separate spec/PR.

## Config Surface (unchanged)

Both services already read `AWS_COGNITO_REGION`, `AWS_COGNITO_USER_POOL_ID`, `AWS_COGNITO_CLIENT_ID`
and feed them to `NewVerifier(region, poolID, clientID)`. Saruman keeps that exact signature, so no
env or secret changes are required.

## Testing

### cognito (the security core)
Sign test JWTs with a throwaway RSA key backed by a stub JWKS. Assert `Verify`:
- **rejects**: wrong issuer, wrong `client_id`, `token_use != "access"` (incl. a real ID token),
  expired, `alg=none`, HS256 (algorithm-confusion), tampered signature.
- **accepts**: a well-formed access token.
- `Claims` accessors: valid UUID; missing claim; non-UUID string; wrong JSON type.

Port and consolidate the stronger assertions from the existing `auth_test.go` in both services.

### ginauth
Table-driven over `Middleware` with a stub `Verifier` (no network):
- missing / malformed bearer; each claim failure; `RequireUserID` on with/without the claim.
- hook returning each sentinel `AuthError` → mapped status; hook returning a raw error → 500;
  hook `nil` → allow.
- happy path sets both context keys.

### Mutation check
Break one `Verify` guard at a time (drop `token_use`, drop `client_id`, widen `WithValidMethods`)
and confirm a test goes red — proves the tests pin the security properties, not just coverage.

## Error Handling Posture

- `NewVerifier` errors if JWKS bootstrap fails → service fails fast at startup (as today).
- `Verify` never panics; every failure is a returned error mapped to 401.
- `MustGetTenantID` / `MustGetUserID` panic if called without the middleware (programming error;
  matches today's contract).
- Transient JWKS-endpoint outages are absorbed by `keyfunc`'s cached auto-refresh (last good key set
  keeps serving) rather than failing every request.

## Open Risks

- **Module path casing.** Repo remote is `github.com/ClusterBox/saruman`; module path is declared
  lowercase `github.com/clusterbox/saruman` to match smaug. GitHub redirects are case-insensitive so
  `go get` resolves, but Go treats the two strings as distinct import paths — every consumer must use
  the lowercase form consistently. Documented so it stays a deliberate choice, not an accident.
- **Version coupling.** A breaking change to saruman's API requires a coordinated bump in both
  services. Mitigated by keeping the surface small and using semver tags.
