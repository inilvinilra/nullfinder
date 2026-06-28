package passive

import (
	"context"
	"net/http"
	"os"
	"time"

	"nullfinder/internal/config"
)

// HTTPClient is the shared custom HTTP client for passive providers.
var HTTPClient = http.DefaultClient

var providerConfig config.ProvidersConfig

// Configure stores the active provider configuration for credential-aware providers.
func Configure(cfg *config.Config) {
	if cfg == nil {
		providerConfig = config.ProvidersConfig{}
		return
	}
	providerConfig = cfg.Providers
}

func securityTrailsAPIKey() string {
	if providerConfig.SecurityTrails.APIKey != "" {
		return providerConfig.SecurityTrails.APIKey
	}
	if providerConfig.SecurityTrails.APIKeyEnv != "" {
		return os.Getenv(providerConfig.SecurityTrails.APIKeyEnv)
	}
	return os.Getenv("SECURITYTRAILS_API_KEY")
}

func shodanAPIKey() string {
	if providerConfig.Shodan.APIKey != "" {
		return providerConfig.Shodan.APIKey
	}
	if providerConfig.Shodan.APIKeyEnv != "" {
		return os.Getenv(providerConfig.Shodan.APIKeyEnv)
	}
	return os.Getenv("SHODAN_API_KEY")
}

func censysCredentials() (string, string) {
	apiID := providerConfig.Censys.APIID
	if apiID == "" {
		if providerConfig.Censys.APIIDEnv != "" {
			apiID = os.Getenv(providerConfig.Censys.APIIDEnv)
		} else {
			apiID = os.Getenv("CENSYS_API_ID")
		}
	}
	apiSecret := providerConfig.Censys.APISecret
	if apiSecret == "" {
		if providerConfig.Censys.APISecretEnv != "" {
			apiSecret = os.Getenv(providerConfig.Censys.APISecretEnv)
		} else {
			apiSecret = os.Getenv("CENSYS_API_SECRET")
		}
	}
	return apiID, apiSecret
}

// ProviderType categorizes providers by authentication requirements.
type ProviderType string

const (
	ProviderPublicNoKey ProviderType = "public_no_key"
	ProviderAPIKey      ProviderType = "api_key_required"
)

// SubdomainResult holds a raw discovery returned from a single provider query.
type SubdomainResult struct {
	Subdomain    string       `json:"subdomain"`
	Source       string       `json:"source"`
	Confidence   int          `json:"confidence"`
	FirstSeen    time.Time    `json:"first_seen"`
	Provider     string       `json:"provider"`
	ProviderType ProviderType `json:"provider_type"`
}

// PassiveProvider defines the methods required for passive OSINT client engines.
type PassiveProvider interface {
	Name() string
	Type() ProviderType
	RequiresAPIKey() bool
	Enabled(cfg *config.Config) bool
	Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error)
}
