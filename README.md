# Saruman

Shared AWS Cognito access-token verification for Clusterbox Go services — one
auditable implementation of `Verify` instead of a copy in every repo.

```
go get github.com/clusterbox/saruman@v0.1.0
```

> The module path is lowercase `github.com/clusterbox/saruman` even though the
> GitHub org is `ClusterBox`. Always import the lowercase form.

## Packages

- **`cognito`** — framework-agnostic (no gin, no DB): `NewVerifier` /
  `Verify` against the pool's cached, auto-refreshing JWKS, typed claim
  accessors (`TenantID`, `UserID`, `Subject`), and `ExtractBearer`.
- **`ginauth`** — the gin middleware: bearer extraction, verification, claim
  validation, and an injectable per-service hook. Error bodies are the
  services' historical `{"error", "message"}` shapes, byte-for-byte.

Tenant (and user) identity is read **only** from verified token claims — never
trusted from a header, body, query, or path parameter on its own. The one
refinement: an opted-in route (`ginauth.Options.AllowCorporateAdmin`) may let a
caller SELECT among tenants their own signed claim already grants via an
`X-Business-Id` header — the header picks WHICH, the claim gates WHETHER.

## Usage

Token-only (legolas):

```go
verifier, err := cognito.NewVerifier(ctx,
    os.Getenv("AWS_COGNITO_REGION"),
    os.Getenv("AWS_COGNITO_USER_POOL_ID"),
    os.Getenv("AWS_COGNITO_CLIENT_ID"),
)
// handle err: fail fast at startup

r.Use(ginauth.Middleware(verifier, ginauth.Options{}))
```

With a tenant-status check (smaug):

```go
r.Use(ginauth.Middleware(verifier, ginauth.Options{
    OnTenantResolved: func(ctx context.Context, tenantID uuid.UUID) error {
        // return nil to allow,
        // a ginauth sentinel (ErrTenantSuspended, ...) for a mapped response,
        // any other error for a logged 500 — a DB outage is not an auth failure.
        return checkTenantStatus(ctx, tenantID)
    },
}))
```

In handlers:

```go
tenantID := ginauth.MustGetTenantID(c) // panics if middleware didn't run
tenantID, ok := ginauth.GetTenantID(c) // non-panicking form
```

`Options.RequireUserID` stays `false` until the pre-token-generation Lambda
stamps a `userId` claim; only then do `MustGetUserID` / `GetUserID` become
available on protected routes.

## Testing consumers

Stub the `cognito.Verifier` interface; build claims with
`cognito.NewClaimsForTest(jwt.MapClaims{...})`. No live JWKS needed.
