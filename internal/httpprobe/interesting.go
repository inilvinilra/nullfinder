package httpprobe

import (
	"strings"
)

var interestingTitleKeywords = []string{
	"admin", "login", "dashboard", "jenkins", "jira", "gitlab", "kibana",
	"grafana", "setup", "config", "portal", "private", "intranet", "db",
	"database", "api", "swagger", "control panel", "signin", "console",
	"management", "nagios", "cpanel", "webmin", "phpmyadmin", "sso",
	"forgot password", "reset password", "account login", "secure login",
	"access denied", "authentication required", "authorization required",
	"sign in", "sign up", "member login", "administrator", "back office",
	"internal use", "employee portal", "self service", "support portal",
	"knowledge base", "service desk", "help desk", "index of /",
}

var interestingHeaderKeywords = []struct {
	header string
	needle string
	reason string
}{
	{"Server", "jenkins", "Server header indicates sensitive backend: Jenkins"},
	{"Server", "jetty", "Server header indicates sensitive backend: Jetty"},
	{"Server", "kibana", "Server header indicates sensitive backend: Kibana"},
	{"Server", "grafana", "Server header indicates sensitive backend: Grafana"},
	{"Server", "phpmyadmin", "Server header indicates phpMyAdmin"},
	{"Server", "webmin", "Server header indicates Webmin"},
	{"Server", "cpanel", "Server header indicates cPanel"},
	{"Server", "nginx", ""},
	{"Server", "apache", ""},
	{"X-Redirect-By", "wordpress", "Redirect powered by WordPress"},
	{"X-Redirect-By", "laravel", "Redirect powered by Laravel"},
	{"X-Redirect-By", "symfony", "Redirect powered by Symfony"},
	{"X-Generator", "wordpress", "Generator indicates WordPress"},
}

// IsInteresting applies heuristical checks on response attributes to detect administrative interfaces,
// control consoles, or protected assets. Returns a boolean and a reason.
func IsInteresting(statusCode int, title string, headers map[string]string) (bool, string) {
	titleLower := strings.ToLower(title)

	// 1. Title checks
	for _, kw := range interestingTitleKeywords {
		if strings.Contains(titleLower, kw) {
			return true, "Title contains keyword: " + kw
		}
	}

	if statusCode == 302 || statusCode == 307 || statusCode == 308 {
		for _, kw := range []string{"login", "signin", "auth", "admin", "portal", "sso"} {
			if strings.Contains(titleLower, kw) {
				return true, "Redirect response points to authentication or admin flow"
			}
		}
	}

	// 2. Header audits
	for k, v := range headers {
		kLower := strings.ToLower(k)
		vLower := strings.ToLower(v)

		if kLower == "www-authenticate" {
			if strings.Contains(vLower, "basic") || strings.Contains(vLower, "digest") {
				return true, "Basic/Digest authentication prompt found"
			}
		}

		for _, hint := range interestingHeaderKeywords {
			if kLower == strings.ToLower(hint.header) && strings.Contains(vLower, hint.needle) {
				if hint.reason != "" {
					return true, hint.reason
				}
			}
		}

		if kLower == "set-cookie" {
			for _, cookieHint := range []string{"session", "auth", "sso", "csrf", "phpmyadmin", "jenkins", "remember"} {
				if strings.Contains(vLower, cookieHint) {
					return true, "Authentication-related cookie found: " + cookieHint
				}
			}
		}
	}

	// 3. Status codes
	if statusCode == 401 {
		return true, "Status code is 401 Unauthorized"
	}
	if statusCode == 403 {
		return true, "Status code is 403 Forbidden"
	}

	return false, ""
}
