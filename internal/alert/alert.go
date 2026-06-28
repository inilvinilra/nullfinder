package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/logx"
)

// AlertPayload defines the structured notification body sent to endpoints.
type AlertPayload struct {
	Domain      string   `json:"domain"`
	NewSubs     []string `json:"new_subdomains"`
	NewPorts    []string `json:"new_ports"`
	NewServices []string `json:"new_services"`
	Timestamp   string   `json:"timestamp"`
}

// SendAlert evaluates configured webhooks and fires notifications if changes occurred.
func SendAlert(cfg *config.Config, domain string, newSubs []string, newPorts []string, newWeb []string) error {
	if len(newSubs) == 0 && len(newPorts) == 0 && len(newWeb) == 0 {
		return nil
	}

	payload := AlertPayload{
		Domain:      domain,
		NewSubs:     newSubs,
		NewPorts:    newPorts,
		NewServices: newWeb,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	// 1. Slack Webhook
	if cfg.Alerting.SlackWebhookURL != "" {
		if err := sendSlackAlert(cfg.Alerting.SlackWebhookURL, payload); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to dispatch Slack alert")
		}
	}

	// 2. Discord Webhook
	if cfg.Alerting.DiscordWebhookURL != "" {
		if err := sendDiscordAlert(cfg.Alerting.DiscordWebhookURL, payload); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to dispatch Discord alert")
		}
	}

	// 3. Custom Webhook (Generic JSON POST)
	if cfg.Alerting.CustomWebhookURL != "" {
		if err := sendCustomAlert(cfg.Alerting.CustomWebhookURL, payload); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to dispatch custom JSON alert")
		}
	}

	return nil
}

func sendSlackAlert(url string, p AlertPayload) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🚨 *NullFinder Scan Alerts for %s*\n", p.Domain))

	if len(p.NewSubs) > 0 {
		sb.WriteString(fmt.Sprintf("• *New Subdomains discovered (%d):*\n", len(p.NewSubs)))
		for _, s := range p.NewSubs {
			sb.WriteString(fmt.Sprintf("   - `%s`\n", s))
		}
	}
	if len(p.NewPorts) > 0 {
		sb.WriteString(fmt.Sprintf("• *New TCP Ports opened (%d):*\n", len(p.NewPorts)))
		for _, pt := range p.NewPorts {
			sb.WriteString(fmt.Sprintf("   - `%s`\n", pt))
		}
	}
	if len(p.NewServices) > 0 {
		sb.WriteString(fmt.Sprintf("• *New Web Services online (%d):*\n", len(p.NewServices)))
		for _, w := range p.NewServices {
			sb.WriteString(fmt.Sprintf("   - <%s|%s>\n", w, w))
		}
	}

	bodyMap := map[string]string{
		"text": sb.String(),
	}
	return postJSON(url, bodyMap)
}

func sendDiscordAlert(url string, p AlertPayload) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🚨 **NullFinder Scan Alerts for %s**\n", p.Domain))

	if len(p.NewSubs) > 0 {
		sb.WriteString(fmt.Sprintf("**New Subdomains discovered (%d):**\n", len(p.NewSubs)))
		for _, s := range p.NewSubs {
			sb.WriteString(fmt.Sprintf("• `%s`\n", s))
		}
	}
	if len(p.NewPorts) > 0 {
		sb.WriteString(fmt.Sprintf("**New TCP Ports opened (%d):**\n", len(p.NewPorts)))
		for _, pt := range p.NewPorts {
			sb.WriteString(fmt.Sprintf("• `%s`\n", pt))
		}
	}
	if len(p.NewServices) > 0 {
		sb.WriteString(fmt.Sprintf("**New Web Services online (%d):**\n", len(p.NewServices)))
		for _, w := range p.NewServices {
			sb.WriteString(fmt.Sprintf("• %s\n", w))
		}
	}

	bodyMap := map[string]string{
		"content": sb.String(),
	}
	return postJSON(url, bodyMap)
}

func sendCustomAlert(url string, p AlertPayload) error {
	return postJSON(url, p)
}

func postJSON(url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("response HTTP status error: %d", resp.StatusCode)
	}

	return nil
}
