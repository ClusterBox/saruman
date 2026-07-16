// Package cognito verifies AWS Cognito access tokens for Clusterbox Go
// services. It is framework-agnostic: no gin, no database.
package cognito

import "strings"

// ExtractBearer returns the token from an "Authorization: Bearer <t>" header
// value, or "" if the header is absent or malformed. Framework-free.
func ExtractBearer(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
