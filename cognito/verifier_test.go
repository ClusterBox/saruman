package cognito

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	testIssuer   = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST"
	testClientID = "test-client-id"
	testKID      = "test-key"
	testOctKID   = "oct-key"
)

// testHMACSecret backs an "oct" key planted in the stub JWKS so the RS256-only
// guard is pinned: if WithValidMethods were widened to HS256, the token signed
// with this secret would VERIFY, and the mutation test would go red.
var testHMACSecret = []byte("test-hmac-secret")

// newTestVerifier builds a CognitoVerifier backed by a throwaway RSA key and a
// stub (in-memory) JWKS — no network.
func newTestVerifier(t *testing.T) (*CognitoVerifier, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":%q,"n":%q,"e":%q},{"kty":"oct","alg":"HS256","use":"sig","kid":%q,"k":%q}]}`,
		testKID,
		base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
		testOctKID,
		base64.RawURLEncoding.EncodeToString(testHMACSecret),
	)
	k, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwks))
	if err != nil {
		t.Fatal(err)
	}
	return &CognitoVerifier{keyfunc: k, issuer: testIssuer, clientID: testClientID}, priv
}

func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":       testIssuer,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "access",
		"client_id": testClientID,
		"sub":       "cognito-sub-1",
		"tenantId":  uuid.New().String(),
	}
}

func sign(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	raw, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerify_AcceptsWellFormedAccessToken(t *testing.T) {
	v, priv := newTestVerifier(t)
	claims := baseClaims()
	got, err := v.Verify(sign(t, priv, claims))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	tid, err := got.TenantID()
	if err != nil || tid.String() != claims["tenantId"] {
		t.Fatalf("TenantID() = (%v, %v), want %v", tid, err, claims["tenantId"])
	}
	if got.Subject() != "cognito-sub-1" {
		t.Fatalf("Subject() = %q", got.Subject())
	}
}

func TestVerify_Rejects(t *testing.T) {
	v, priv := newTestVerifier(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(f func(jwt.MapClaims)) string {
		c := baseClaims()
		f(c)
		return sign(t, priv, c)
	}

	cases := []struct {
		name string
		raw  string
	}{
		{"wrong issuer", mutate(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" })},
		{"wrong client_id", mutate(func(c jwt.MapClaims) { c["client_id"] = "other-client" })},
		{"id token (token_use)", mutate(func(c jwt.MapClaims) { c["token_use"] = "id" })},
		{"missing token_use", mutate(func(c jwt.MapClaims) { delete(c, "token_use") })},
		{"expired", mutate(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })},
		{"missing exp", mutate(func(c jwt.MapClaims) { delete(c, "exp") })},
		{"tampered signature", func() string {
			raw := sign(t, priv, baseClaims())
			return raw[:len(raw)-3] + "xxx"
		}()},
		{"signed by unknown key", func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, baseClaims())
			tok.Header["kid"] = testKID
			raw, err := tok.SignedString(otherKey)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}()},
		{"alg none", func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
			raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}()},
		{"HS256 algorithm confusion", func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
			tok.Header["kid"] = testKID
			raw, err := tok.SignedString([]byte("secret"))
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}()},
		{"HS256 signed with known symmetric key", func() string {
			// Verifiable if HS256 were ever allowed; only WithValidMethods
			// (RS256-only) rejects it. Pins the algorithm allowlist.
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
			tok.Header["kid"] = testOctKID
			raw, err := tok.SignedString(testHMACSecret)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}()},
		{"garbage", "not.a.jwt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(tc.raw); err == nil {
				t.Fatal("Verify() = nil error, want rejection")
			}
		})
	}
}
