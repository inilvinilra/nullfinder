package httpprobe

import (
	"strings"
	"testing"
)

func TestIsInteresting(t *testing.T) {
	tests := []struct {
		statusCode   int
		title        string
		headers      map[string]string
		expectInt    bool
		expectReason string
	}{
		{
			statusCode:   200,
			title:        "Admin Portal Dashboard",
			headers:      nil,
			expectInt:    true,
			expectReason: "Title contains keyword: admin",
		},
		{
			statusCode:   401,
			title:        "Unauthorized",
			headers:      nil,
			expectInt:    true,
			expectReason: "Status code is 401 Unauthorized",
		},
		{
			statusCode:   200,
			title:        "Example Page",
			headers:      map[string]string{"WWW-Authenticate": "Basic realm=\"Restricted\""},
			expectInt:    true,
			expectReason: "Basic/Digest authentication prompt found",
		},
		{
			statusCode:   200,
			title:        "Welcome to our home page",
			headers:      map[string]string{"Server": "Nginx"},
			expectInt:    false,
			expectReason: "",
		},
		{
			statusCode:   200,
			title:        "Example",
			headers:      map[string]string{"X-Redirect-By": "WordPress"},
			expectInt:    true,
			expectReason: "Redirect powered by WordPress",
		},
		{
			statusCode:   200,
			title:        "Example",
			headers:      map[string]string{"Set-Cookie": "sessionid=abc123; Path=/; HttpOnly"},
			expectInt:    true,
			expectReason: "Authentication-related cookie found: session",
		},
		{
			statusCode:   403,
			title:        "Access Denied",
			headers:      nil,
			expectInt:    true,
			expectReason: "Title contains keyword: access denied",
		},
	}

	for _, tc := range tests {
		ok, reason := IsInteresting(tc.statusCode, tc.title, tc.headers)
		if ok != tc.expectInt {
			t.Errorf("IsInteresting(%d, %q, %v) = %t; want %t", tc.statusCode, tc.title, tc.headers, ok, tc.expectInt)
		}
		if tc.expectInt && !strings.Contains(reason, tc.expectReason) {
			t.Errorf("expected reason to contain %q, got %q", tc.expectReason, reason)
		}
	}
}
