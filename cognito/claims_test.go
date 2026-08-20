package cognito

import (
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestClaims_TenantID(t *testing.T) {
	valid := uuid.New()
	cases := []struct {
		name    string
		claims  jwt.MapClaims
		want    uuid.UUID
		missing bool // want ErrClaimMissing
		invalid bool // want a non-missing error
	}{
		{"valid uuid", jwt.MapClaims{"tenantId": valid.String()}, valid, false, false},
		{"absent", jwt.MapClaims{}, uuid.Nil, true, false},
		{"empty string", jwt.MapClaims{"tenantId": ""}, uuid.Nil, true, false},
		{"wrong JSON type", jwt.MapClaims{"tenantId": 12345}, uuid.Nil, true, false},
		{"not a uuid", jwt.MapClaims{"tenantId": "nope"}, uuid.Nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newClaims(tc.claims).TenantID()
			switch {
			case tc.missing:
				if !errors.Is(err, ErrClaimMissing) {
					t.Fatalf("want ErrClaimMissing, got %v", err)
				}
			case tc.invalid:
				if err == nil || errors.Is(err, ErrClaimMissing) {
					t.Fatalf("want invalid-uuid error, got %v", err)
				}
			default:
				if err != nil || got != tc.want {
					t.Fatalf("got (%v, %v), want (%v, nil)", got, err, tc.want)
				}
			}
		})
	}
}

func TestClaims_UserIDAndSubject(t *testing.T) {
	uid := uuid.New()
	c := newClaims(jwt.MapClaims{"userId": uid.String(), "sub": "cognito-sub-1"})
	got, err := c.UserID()
	if err != nil || got != uid {
		t.Fatalf("UserID() = (%v, %v), want (%v, nil)", got, err, uid)
	}
	if s := c.Subject(); s != "cognito-sub-1" {
		t.Fatalf("Subject() = %q, want %q", s, "cognito-sub-1")
	}
	if _, err := newClaims(jwt.MapClaims{}).UserID(); !errors.Is(err, ErrClaimMissing) {
		t.Fatalf("want ErrClaimMissing, got %v", err)
	}
	if s := newClaims(jwt.MapClaims{}).Subject(); s != "" {
		t.Fatalf("Subject() on empty claims = %q, want \"\"", s)
	}
}

func TestClaims_CorporateBusinessIDs(t *testing.T) {
	a := uuid.New()
	b := uuid.New()
	cases := []struct {
		name    string
		claims  jwt.MapClaims
		want    []uuid.UUID
		missing bool // want ErrClaimMissing
		invalid bool // want a non-missing error
	}{
		{"absent", jwt.MapClaims{}, nil, true, false},
		{"empty string", jwt.MapClaims{"corpBusinessIds": ""}, nil, true, false},
		{"wrong JSON type", jwt.MapClaims{"corpBusinessIds": 12345}, nil, true, false},
		{"one id", jwt.MapClaims{"corpBusinessIds": a.String()}, []uuid.UUID{a}, false, false},
		{"two ids", jwt.MapClaims{"corpBusinessIds": a.String() + "," + b.String()}, []uuid.UUID{a, b}, false, false},
		{"ids with spaces", jwt.MapClaims{"corpBusinessIds": a.String() + ", " + b.String()}, []uuid.UUID{a, b}, false, false},
		{"only commas", jwt.MapClaims{"corpBusinessIds": ","}, nil, true, false},
		{"trailing comma", jwt.MapClaims{"corpBusinessIds": a.String() + ","}, []uuid.UUID{a}, false, false},
		{"contains a non-uuid entry", jwt.MapClaims{"corpBusinessIds": a.String() + ",nope"}, nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newClaims(tc.claims).CorporateBusinessIDs()
			switch {
			case tc.missing:
				if !errors.Is(err, ErrClaimMissing) {
					t.Fatalf("want ErrClaimMissing, got %v", err)
				}
			case tc.invalid:
				if err == nil || errors.Is(err, ErrClaimMissing) {
					t.Fatalf("want invalid-uuid error, got %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(got) != len(tc.want) {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
				for i := range tc.want {
					if got[i] != tc.want[i] {
						t.Fatalf("got %v, want %v", got, tc.want)
					}
				}
			}
		})
	}
}
