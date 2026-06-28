package config

import (
	"os"

	"github.com/spf13/viper"
)

// LoadConfig reads configuration settings from a file path (optional) or searches default paths.
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	SetDefaults(v)

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config.yaml in working directory or subfolders
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	// Make Viper aware of environment variables
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// Suppress file-not-found errors to support environment-only/default scans
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Dynamically hydrate API secrets from environment keys
	hydrateEnvKeys(&cfg)

	return &cfg, nil
}

func hydrateEnvKeys(cfg *Config) {
	// SecurityTrails
	if cfg.Providers.SecurityTrails.APIKeyEnv != "" {
		cfg.Providers.SecurityTrails.APIKey = os.Getenv(cfg.Providers.SecurityTrails.APIKeyEnv)
	}
	// Shodan
	if cfg.Providers.Shodan.APIKeyEnv != "" {
		cfg.Providers.Shodan.APIKey = os.Getenv(cfg.Providers.Shodan.APIKeyEnv)
	}
	// Censys
	if cfg.Providers.Censys.APIIDEnv != "" {
		cfg.Providers.Censys.APIID = os.Getenv(cfg.Providers.Censys.APIIDEnv)
	}
	if cfg.Providers.Censys.APISecretEnv != "" {
		cfg.Providers.Censys.APISecret = os.Getenv(cfg.Providers.Censys.APISecretEnv)
	}
}
