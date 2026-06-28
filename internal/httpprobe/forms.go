package httpprobe

import "strings"

// DetectLoginForm applies lightweight HTML heuristics for authentication forms.
func DetectLoginForm(body string) bool {
	bodyLower := strings.ToLower(body)
	if !strings.Contains(bodyLower, "<form") {
		return false
	}
	if strings.Contains(bodyLower, "type=\"password\"") || strings.Contains(bodyLower, "type='password'") {
		return true
	}
	if strings.Contains(bodyLower, "name=\"password\"") || strings.Contains(bodyLower, "name='password'") {
		return true
	}
	if strings.Contains(bodyLower, "signin") || strings.Contains(bodyLower, "log in") || strings.Contains(bodyLower, "login") {
		return true
	}
	return false
}
