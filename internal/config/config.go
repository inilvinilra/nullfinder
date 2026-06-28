package config

// Config aggregates all sub-configuration namespaces for the application.
type Config struct {
	Mode      string          `mapstructure:"mode"`
	Scan      ScanConfig      `mapstructure:"scan"`
	Enum      EnumConfig      `mapstructure:"enum"`
	Providers ProvidersConfig `mapstructure:"providers"`
	DNS       DNSConfig       `mapstructure:"dns"`
	HTTP      HTTPConfig      `mapstructure:"http"`
	PortScan  PortScanConfig  `mapstructure:"portscan"`
	Output    OutputConfig    `mapstructure:"output"`
	Storage   StorageConfig   `mapstructure:"storage"`
	Scheduler SchedulerConfig `mapstructure:"scheduler"`
	Alerting  AlertingConfig  `mapstructure:"alerting"`
}

// SchedulerJob holds target scanning frequency rules.
type SchedulerJob struct {
	Domain   string `mapstructure:"domain"`
	Interval string `mapstructure:"interval"`
	Mode     string `mapstructure:"mode"`
}

// SchedulerConfig governs background cron tasks.
type SchedulerConfig struct {
	Enabled bool           `mapstructure:"enabled"`
	Jobs    []SchedulerJob `mapstructure:"jobs"`
}

// AlertingConfig defines Slack/Discord/custom notification endpoints.
type AlertingConfig struct {
	SlackWebhookURL   string `mapstructure:"slack_webhook_url"`
	DiscordWebhookURL string `mapstructure:"discord_webhook_url"`
	CustomWebhookURL  string `mapstructure:"custom_webhook_url"`
}

// ScanConfig governs overall execution concurrency, depth, safety, and timeouts.
type ScanConfig struct {
	DefaultProfile     string `mapstructure:"default_profile"`
	Threads            int    `mapstructure:"threads"`
	TimeoutSeconds     int    `mapstructure:"timeout_seconds"`
	RateLimitPerSecond int    `mapstructure:"rate_limit_per_second"`
	SafeOnly           bool   `mapstructure:"safe_only"`
	MaxDepth           int    `mapstructure:"max_depth"`
}

// EnumConfig controls local wordlists and permutations.
type EnumConfig struct {
	LocalWordlistEnabled     bool   `mapstructure:"local_wordlist_enabled"`
	LocalPermutationEnabled  bool   `mapstructure:"local_permutation_enabled"`
	MaxPermutationsPerDomain int    `mapstructure:"max_permutations_per_domain"`
	Wordlist                 string `mapstructure:"wordlist"`
}

// ProviderConfig maps configurations and key sources for passive OSINT providers.
type ProviderConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	RequiresAPIKey bool   `mapstructure:"requires_api_key"`
	APIKeyEnv      string `mapstructure:"api_key_env"`
	APIIDEnv       string `mapstructure:"api_id_env"`     // specifically for Censys ID
	APISecretEnv   string `mapstructure:"api_secret_env"` // specifically for Censys Secret
	TimeoutSeconds int    `mapstructure:"timeout_seconds"`
	APIKey         string // Hydrated dynamically from OS environment
	APIID          string // Hydrated dynamically from OS environment
	APISecret      string // Hydrated dynamically from OS environment
}

// ProvidersConfig groups configuration parameters for all passive providers.
type ProvidersConfig struct {
	Crtsh          ProviderConfig `mapstructure:"crtsh"`
	WebArchive     ProviderConfig `mapstructure:"webarchive"`
	SecurityTrails ProviderConfig `mapstructure:"securitytrails"`
	Censys         ProviderConfig `mapstructure:"censys"`
	Shodan         ProviderConfig `mapstructure:"shodan"`
	HackerTarget   ProviderConfig `mapstructure:"hackertarget"`
	Anubis         ProviderConfig `mapstructure:"anubis"`
	AlienVault     ProviderConfig `mapstructure:"alienvault"`
	ThreatCrowd    ProviderConfig `mapstructure:"threatcrowd"`
	CertSpotter    ProviderConfig `mapstructure:"certspotter"`
	URLScan        ProviderConfig `mapstructure:"urlscan"`
	CommonCrawl    ProviderConfig `mapstructure:"commoncrawl"`
	RapidDNS       ProviderConfig `mapstructure:"rapiddns"`
	THC            ProviderConfig `mapstructure:"thc"`
}

// DNSConfig specifies resolver details, timeouts, retries, and wildcard rules.
type DNSConfig struct {
	ResolverMode            string   `mapstructure:"resolver_mode"`
	FallbackPublicResolvers bool     `mapstructure:"fallback_public_resolvers"`
	TimeoutSeconds          int      `mapstructure:"timeout_seconds"`
	Retries                 int      `mapstructure:"retries"`
	WildcardDetection       bool     `mapstructure:"wildcard_detection"`
	Resolvers               []string `mapstructure:"resolvers"`
}

// HTTPConfig specifies HTTP/HTTPS probing setups.
type HTTPConfig struct {
	Enabled         bool  `mapstructure:"enabled"`
	TimeoutSeconds  int   `mapstructure:"timeout_seconds"`
	FollowRedirects bool  `mapstructure:"follow_redirects"`
	MaxRedirects    int   `mapstructure:"max_redirects"`
	MaxBodyBytes    int64 `mapstructure:"max_body_bytes"`
	Ports           []int `mapstructure:"ports"`
}

// PortScanConfig defines parameters for safe native port scanning.
type PortScanConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	Profile            string `mapstructure:"profile"`
	TimeoutSeconds     int    `mapstructure:"timeout_seconds"`
	Workers            int    `mapstructure:"workers"`
	RateLimitPerSecond int    `mapstructure:"rate_limit_per_second"`
	WebPorts           []int  `mapstructure:"web_ports"`
	CommonPorts        []int  `mapstructure:"common_ports"`
}

// OutputConfig sets reporting specifications.
type OutputConfig struct {
	Formats []string `mapstructure:"formats"`
}

// StorageConfig configures Bbolt database rules.
type StorageConfig struct {
	Type string `mapstructure:"type"`
	Path string `mapstructure:"path"`
}
