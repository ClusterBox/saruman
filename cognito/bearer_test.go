package cognito

import "testing"

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{"valid", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"case-insensitive scheme", "bearer tok", "tok"},
		{"empty header", "", ""},
		{"scheme only", "Bearer", ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz", ""},
		{"surrounding whitespace trimmed", "Bearer   tok  ", "tok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractBearer(tc.header); got != tc.want {
				t.Fatalf("ExtractBearer(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
