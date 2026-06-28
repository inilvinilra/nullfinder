package httpprobe

import (
	"regexp"
	"sort"
	"strings"
)

var generatorRegex = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

var (
	frameworkHeaderHints = []struct {
		header string
		needle string
		tech   string
	}{
		{"X-Powered-By", "express", "express"},
		{"X-Powered-By", "php", "php"},
		{"X-Powered-By", "asp.net", "asp.net"},
		{"X-AspNet-Version", "", "asp.net"},
		{"X-AspNetMvc-Version", "", "asp.net mvc"},
		{"X-Generator", "", "generator"},
		{"Server", "cloudflare", "cloudflare"},
		{"Server", "nginx", "nginx"},
		{"Server", "apache", "apache"},
		{"Server", "caddy", "caddy"},
		{"Server", "openresty", "openresty"},
		{"Server", "litespeed", "litespeed"},
		{"Server", "iis", "iis"},
		{"Server", "jetty", "jetty"},
		{"Server", "tomcat", "tomcat"},
	}

	bodyTechHints = []string{
		"wordpress",
		"drupal",
		"joomla",
		"grafana",
		"jenkins",
		"kibana",
		"gitlab",
		"next.js",
		"nextjs",
		"react",
		"vue",
		"angular",
		"django",
		"flask",
		"laravel",
		"symfony",
		"rails",
		"bootstrap",
		"tailwind",
		"alpine.js",
	}
)

// DetectTechnologies derives stack hints from headers and limited HTML content.
func DetectTechnologies(headers map[string]string, body string) []string {
	set := make(map[string]struct{})

	for _, hint := range frameworkHeaderHints {
		value := strings.ToLower(headers[hint.header])
		if value == "" {
			continue
		}
		if hint.needle == "" || strings.Contains(value, hint.needle) {
			set[hint.tech] = struct{}{}
		}
	}

	bodyLower := strings.ToLower(body)
	for _, tech := range bodyTechHints {
		if strings.Contains(bodyLower, tech) {
			set[tech] = struct{}{}
		}
	}

	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
		set["wordpress"] = struct{}{}
	}
	if strings.Contains(bodyLower, "drupal-settings-json") {
		set["drupal"] = struct{}{}
	}
	if strings.Contains(bodyLower, "csrf-token") && strings.Contains(bodyLower, "laravel") {
		set["laravel"] = struct{}{}
	}
	if strings.Contains(bodyLower, "django") || strings.Contains(bodyLower, "csrfmiddlewaretoken") {
		set["django"] = struct{}{}
	}

	if match := generatorRegex.FindStringSubmatch(body); len(match) > 1 {
		set[strings.TrimSpace(match[1])] = struct{}{}
	}

	var techs []string
	for tech := range set {
		techs = append(techs, tech)
	}
	sort.Strings(techs)
	return techs
}
