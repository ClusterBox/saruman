package cognito

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrClaimMissing reports that a required claim is absent from the token (or
// not a string, which the services have always treated the same as absent).
var ErrClaimMissing = errors.New("claim missing")

// Claims wraps the verified JWT claims with typed, validated accessors.
type Claims struct {
	m jwt.MapClaims
}

func newClaims(m jwt.MapClaims) *Claims { return &Claims{m: m} }

// NewClaimsForTest wraps raw claims for stub Verifiers in consumer tests.
// Production claims always come from CognitoVerifier.Verify.
func NewClaimsForTest(m jwt.MapClaims) *Claims { return newClaims(m) }

// TenantID returns the verified tenantId claim.
func (c *Claims) TenantID() (uuid.UUID, error) { return c.uuidClaim("tenantId") }

// UserID returns the verified userId claim. The pre-token Lambda does not
// stamp it yet; see ginauth.Options.RequireUserID.
func (c *Claims) UserID() (uuid.UUID, error) { return c.uuidClaim("userId") }

// Subject returns the Cognito sub, or "" if absent.
func (c *Claims) Subject() string {
	s, _ := c.m["sub"].(string)
	return s
}

func (c *Claims) uuidClaim(name string) (uuid.UUID, error) {
	s, _ := c.m[name].(string)
	if s == "" {
		return uuid.Nil, fmt.Errorf("%s: %w", name, ErrClaimMissing)
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s claim is not a valid UUID: %w", name, err)
	}
	return id, nil
}
