package httpprobe

import "testing"

func TestDetectTechnologies(t *testing.T) {
	headers := map[string]string{
		"Server":           "cloudflare",
		"X-Powered-By":     "PHP/8.2",
		"X-AspNet-Version": "4.0.30319",
	}
	body := `<html><head><meta name="generator" content="WordPress 6.5"><script src="/wp-content/app.js"></script></head><body>wordpress react next.js csrfmiddlewaretoken</body></html>`

	techs := DetectTechnologies(headers, body)
	expected := map[string]bool{
		"cloudflare":    true,
		"php":           true,
		"asp.net":       true,
		"wordpress":     true,
		"WordPress 6.5": true,
		"react":         true,
		"next.js":       true,
		"django":        true,
	}

	for _, tech := range techs {
		delete(expected, tech)
	}
	if len(expected) != 0 {
		t.Fatalf("missing expected technologies: %v", expected)
	}
}
