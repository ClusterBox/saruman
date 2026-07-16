package cognito

import (
	"context"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates a raw JWT and returns its claims. An interface so
// callers and tests can stub without a live JWKS endpoint.
type Verifier interface {
	Verify(raw string) (*Claims, error)
}

// CognitoVerifier verifies Cognito ACCESS tokens against the pool's JWKS.
type CognitoVerifier struct {
	keyfunc  keyfunc.Keyfunc
	issuer   string
	clientID string
}

// NewVerifier builds a verifier with a CACHED, auto-refreshing JWKS. Fetching
// the JWKS per request would add a network call to every request and get
// rate-limited.
func NewVerifier(ctx context.Context, region, poolID, clientID string) (*CognitoVerifier, error) {
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, poolID)

	k, err := keyfunc.NewDefaultCtx(ctx, []string{issuer + "/.well-known/jwks.json"})
	if err != nil {
		return nil, fmt.Errorf("build cognito jwks keyfunc: %w", err)
	}

	return &CognitoVerifier{keyfunc: k, issuer: issuer, clientID: clientID}, nil
}

// Verify checks signature, issuer, expiry, and that this is an ACCESS token
// for our client. A valid signature alone is not enough: an ID token is also
// validly signed by the same pool but is not an access token.
func (v *CognitoVerifier) Verify(raw string) (*Claims, error) {
	token, err := jwt.Parse(raw, v.keyfunc.Keyfunc,
		jwt.WithIssuer(v.issuer),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	if use, _ := claims["token_use"].(string); use != "access" {
		return nil, fmt.Errorf("token_use is %q, want \"access\"", use)
	}
	if cid, _ := claims["client_id"].(string); cid != v.clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}

	return newClaims(claims), nil
}
