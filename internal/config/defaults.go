package config

import "github.com/spf13/viper"

// SetDefaults assigns initial values to configuration keys in the given Viper instance.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("mode", "hybrid")

	// Global scan defaults
	v.SetDefault("scan.default_profile", "web")
	v.SetDefault("scan.threads", 25)
	v.SetDefault("scan.timeout_seconds", 10)
	v.SetDefault("scan.rate_limit_per_second", 25)
	v.SetDefault("scan.safe_only", true)
	v.SetDefault("scan.max_depth", 1)

	// Enumeration defaults
	v.SetDefault("enum.local_wordlist_enabled", true)
	v.SetDefault("enum.local_permutation_enabled", false)
	v.SetDefault("enum.max_permutations_per_domain", 5000)
	v.SetDefault("enum.wordlist", "wordlists/small.txt")

	// OSINT Providers
	v.SetDefault("providers.crtsh.enabled", true)
	v.SetDefault("providers.crtsh.requires_api_key", false)
	v.SetDefault("providers.crtsh.timeout_seconds", 20)

	v.SetDefault("providers.webarchive.enabled", true)
	v.SetDefault("providers.webarchive.requires_api_key", false)
	v.SetDefault("providers.webarchive.timeout_seconds", 20)

	v.SetDefault("providers.securitytrails.enabled", false)
	v.SetDefault("providers.securitytrails.requires_api_key", true)
	v.SetDefault("providers.securitytrails.api_key_env", "SECURITYTRAILS_API_KEY")
	v.SetDefault("providers.securitytrails.timeout_seconds", 20)

	v.SetDefault("providers.censys.enabled", false)
	v.SetDefault("providers.censys.requires_api_key", true)
	v.SetDefault("providers.censys.api_id_env", "CENSYS_API_ID")
	v.SetDefault("providers.censys.api_secret_env", "CENSYS_API_SECRET")
	v.SetDefault("providers.censys.timeout_seconds", 20)

	v.SetDefault("providers.shodan.enabled", false)
	v.SetDefault("providers.shodan.requires_api_key", true)
	v.SetDefault("providers.shodan.api_key_env", "SHODAN_API_KEY")
	v.SetDefault("providers.shodan.timeout_seconds", 20)

	v.SetDefault("providers.hackertarget.enabled", true)
	v.SetDefault("providers.hackertarget.requires_api_key", false)
	v.SetDefault("providers.hackertarget.timeout_seconds", 20)

	v.SetDefault("providers.anubis.enabled", false)
	v.SetDefault("providers.anubis.requires_api_key", false)
	v.SetDefault("providers.anubis.timeout_seconds", 20)

	v.SetDefault("providers.alienvault.enabled", true)
	v.SetDefault("providers.alienvault.requires_api_key", false)
	v.SetDefault("providers.alienvault.timeout_seconds", 20)

	v.SetDefault("providers.threatcrowd.enabled", false)
	v.SetDefault("providers.threatcrowd.requires_api_key", false)
	v.SetDefault("providers.threatcrowd.timeout_seconds", 20)

	v.SetDefault("providers.certspotter.enabled", true)
	v.SetDefault("providers.certspotter.requires_api_key", false)
	v.SetDefault("providers.certspotter.timeout_seconds", 20)

	v.SetDefault("providers.urlscan.enabled", true)
	v.SetDefault("providers.urlscan.requires_api_key", false)
	v.SetDefault("providers.urlscan.timeout_seconds", 20)

	v.SetDefault("providers.commoncrawl.enabled", true)
	v.SetDefault("providers.commoncrawl.requires_api_key", false)
	v.SetDefault("providers.commoncrawl.timeout_seconds", 20)

	v.SetDefault("providers.rapiddns.enabled", true)
	v.SetDefault("providers.rapiddns.requires_api_key", false)
	v.SetDefault("providers.rapiddns.timeout_seconds", 20)

	v.SetDefault("providers.thc.enabled", true)
	v.SetDefault("providers.thc.requires_api_key", false)
	v.SetDefault("providers.thc.timeout_seconds", 20)

	// DNS defaults
	v.SetDefault("dns.resolver_mode", "mixed")
	v.SetDefault("dns.fallback_public_resolvers", true)
	v.SetDefault("dns.timeout_seconds", 5)
	v.SetDefault("dns.retries", 2)
	v.SetDefault("dns.wildcard_detection", true)
	v.SetDefault("dns.resolvers", []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})

	// HTTP Probe defaults
	v.SetDefault("http.enabled", true)
	v.SetDefault("http.timeout_seconds", 5)
	v.SetDefault("http.follow_redirects", true)
	v.SetDefault("http.max_redirects", 5)
	v.SetDefault("http.max_body_bytes", 1048576) // 1MB limit
	v.SetDefault("http.ports", []int{80, 443, 8080, 8443, 8000, 3000, 5000})

	// Portscan defaults
	v.SetDefault("portscan.enabled", false)
	v.SetDefault("portscan.profile", "web")
	v.SetDefault("portscan.timeout_seconds", 3)
	v.SetDefault("portscan.workers", 100)
	v.SetDefault("portscan.rate_limit_per_second", 100)
	v.SetDefault("portscan.web_ports", []int{80, 443, 8080, 8443, 8000, 3000, 5000})
	v.SetDefault("portscan.common_ports", []int{21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 9200})

	// Output formats defaults
	v.SetDefault("output.formats", []string{"txt", "json", "csv", "html"})

	// Storage defaults
	v.SetDefault("storage.type", "bbolt")
	v.SetDefault("storage.path", "nullfinder.db")

	// Scheduler defaults
	v.SetDefault("scheduler.enabled", false)
	v.SetDefault("scheduler.jobs", []interface{}{})

	// Alerting defaults
	v.SetDefault("alerting.slack_webhook_url", "")
	v.SetDefault("alerting.discord_webhook_url", "")
	v.SetDefault("alerting.custom_webhook_url", "")
}
