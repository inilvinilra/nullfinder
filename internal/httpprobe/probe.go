package httpprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"nullfinder/internal/netutil"
)

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

func extractTitle(body string) string {
	match := titleRegex.FindStringSubmatch(body)
	if len(match) > 1 {
		t := strings.TrimSpace(match[1])
		t = strings.ReplaceAll(t, "\n", " ")
		t = strings.ReplaceAll(t, "\r", " ")
		return t
	}
	return ""
}

// ProbeResult stores gathered HTTP/HTTPS service state.
type ProbeResult struct {
	URL                   string            `json:"url"`
	FinalURL              string            `json:"final_url,omitempty"`
	Domain                string            `json:"domain"`
	Port                  int               `json:"port"`
	Scheme                string            `json:"scheme"`
	StatusCode            int               `json:"status_code"`
	ResponseTimeMS        int64             `json:"response_time_ms"`
	ResolvedIP            string            `json:"resolved_ip,omitempty"`
	ResolvedAddress       string            `json:"resolved_address,omitempty"`
	RedirectCount         int               `json:"redirect_count"`
	Title                 string            `json:"title"`
	Server                string            `json:"server,omitempty"`
	ContentType           string            `json:"content_type,omitempty"`
	PoweredBy             string            `json:"powered_by,omitempty"`
	Technologies          []string          `json:"technologies,omitempty"`
	HasLoginForm          bool              `json:"has_login_form"`
	FaviconHash           string            `json:"favicon_hash,omitempty"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	ContentLength         int64             `json:"content_length"`
	Headers               map[string]string `json:"headers"`
	TLSIssuer             string            `json:"tls_issuer,omitempty"`
	TLSExpiry             string            `json:"tls_expiry,omitempty"`
	TLSSubject            string            `json:"tls_subject,omitempty"`
	IsInteresting         bool              `json:"is_interesting"`
	InterestingReason     string            `json:"interesting_reason,omitempty"`
}

// Prober manages active HTTP probing workers and configurations.
type Prober struct {
	ports          []int
	threads        int
	rateLimit      int
	timeout        time.Duration
	followRedirect bool
	maxRedirects   int
	resolvers      []string
	faviconMu      sync.RWMutex
	faviconCache   map[string]string
}

// NewProber initializes a Prober.
func NewProber(ports []int, threads int, rateLimit int, timeoutSeconds int, followRedirect bool, maxRedirects int, resolvers []string) *Prober {
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	if threads <= 0 {
		threads = 10
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	if maxRedirects <= 0 {
		maxRedirects = 5
	}
	return &Prober{
		ports:          ports,
		threads:        threads,
		rateLimit:      rateLimit,
		timeout:        time.Duration(timeoutSeconds) * time.Second,
		followRedirect: followRedirect,
		maxRedirects:   maxRedirects,
		resolvers:      resolvers,
		faviconCache:   make(map[string]string),
	}
}

func schemesForPort(port int) []string {
	switch port {
	case 80:
		return []string{"http"}
	case 443:
		return []string{"https"}
	case 8443, 9443, 10443:
		return []string{"https", "http"}
	case 8080, 8000, 8008, 3000, 5000, 8888:
		return []string{"http", "https"}
	default:
		return []string{"http", "https"}
	}
}

// ProbeSingle executes a GET request against a target schema, domain, and port.
func (p *Prober) ProbeSingle(ctx context.Context, scheme string, domain string, port int) *ProbeResult {
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	url := fmt.Sprintf("%s://%s:%d", scheme, domain, port)
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		url = fmt.Sprintf("%s://%s", scheme, domain)
	}

	req, err := http.NewRequestWithContext(probeCtx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "NullFinder/1.0")

	client := netutil.GetHTTPClient(p.resolvers, p.timeout, true)
	var resolvedIP string
	var resolvedAddress string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if remote := info.Conn.RemoteAddr(); remote != nil {
				resolvedAddress = remote.String()
				if host, _, err := net.SplitHostPort(resolvedAddress); err == nil {
					resolvedIP = host
				} else {
					resolvedIP = resolvedAddress
				}
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	redirectCount := 0
	if !p.followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			redirectCount = len(via)
			if len(via) >= p.maxRedirects {
				return fmt.Errorf("stopped after %d redirects", p.maxRedirects)
			}
			return nil
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	responseTime := time.Since(start)

	bodyReader := io.LimitReader(resp.Body, 1024*1024)
	bodyBytes, _ := io.ReadAll(bodyReader)
	bodyStr := string(bodyBytes)

	title := extractTitle(bodyStr)
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	var tlsIssuer, tlsExpiry, tlsSubject string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		tlsIssuer = cert.Issuer.CommonName
		if tlsIssuer == "" && len(cert.Issuer.Organization) > 0 {
			tlsIssuer = cert.Issuer.Organization[0]
		}
		tlsSubject = cert.Subject.CommonName
		if tlsSubject == "" && len(cert.DNSNames) > 0 {
			tlsSubject = cert.DNSNames[0]
		}
		tlsExpiry = cert.NotAfter.Format("2006-01-02")
	}

	interesting, reason := IsInteresting(resp.StatusCode, title, headers)
	finalURL := resp.Request.URL.String()
	techs := DetectTechnologies(headers, bodyStr)
	hasLoginForm := DetectLoginForm(bodyStr)
	faviconHash := p.fetchFaviconHash(probeCtx, client, finalURL, headers["Content-Type"], resp.StatusCode, bodyStr)
	csp := headers["Content-Security-Policy"]

	return &ProbeResult{
		URL:                   url,
		FinalURL:              finalURL,
		Domain:                domain,
		Port:                  port,
		Scheme:                scheme,
		StatusCode:            resp.StatusCode,
		ResponseTimeMS:        responseTime.Milliseconds(),
		ResolvedIP:            resolvedIP,
		ResolvedAddress:       resolvedAddress,
		RedirectCount:         redirectCount,
		Title:                 title,
		Server:                headers["Server"],
		ContentType:           headers["Content-Type"],
		PoweredBy:             headers["X-Powered-By"],
		Technologies:          techs,
		HasLoginForm:          hasLoginForm,
		FaviconHash:           faviconHash,
		ContentSecurityPolicy: csp,
		ContentLength:         resp.ContentLength,
		Headers:               headers,
		TLSIssuer:             tlsIssuer,
		TLSExpiry:             tlsExpiry,
		TLSSubject:            tlsSubject,
		IsInteresting:         interesting,
		InterestingReason:     reason,
	}
}

func (p *Prober) fetchFaviconHash(ctx context.Context, client *http.Client, pageURL string, contentType string, statusCode int, body string) string {
	if statusCode >= 400 || !strings.Contains(strings.ToLower(contentType), "text/html") {
		return ""
	}
	faviconURL := discoverFaviconURL(pageURL, body)
	if faviconURL == "" {
		return ""
	}
	p.faviconMu.RLock()
	if cached, ok := p.faviconCache[faviconURL]; ok {
		p.faviconMu.RUnlock()
		return cached
	}
	p.faviconMu.RUnlock()

	faviconCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(faviconCtx, "GET", faviconURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "NullFinder/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	reader := io.LimitReader(resp.Body, 128*1024)
	data, err := io.ReadAll(reader)
	if err != nil || len(data) == 0 {
		return ""
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	p.faviconMu.Lock()
	p.faviconCache[faviconURL] = hash
	p.faviconMu.Unlock()

	return hash
}

func discoverFaviconURL(pageURL string, body string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}

	bodyLower := strings.ToLower(body)
	for _, marker := range []string{"rel=\"icon\"", "rel='icon'", "rel=\"shortcut icon\"", "rel='shortcut icon'"} {
		idx := strings.Index(bodyLower, marker)
		if idx == -1 {
			continue
		}
		snippet := body[idx:]
		hrefIdx := strings.Index(strings.ToLower(snippet), "href=")
		if hrefIdx == -1 {
			continue
		}
		hrefPart := snippet[hrefIdx+5:]
		if len(hrefPart) == 0 {
			continue
		}
		quote := hrefPart[0]
		if quote != '"' && quote != '\'' {
			continue
		}
		hrefPart = hrefPart[1:]
		end := strings.IndexByte(hrefPart, quote)
		if end == -1 {
			continue
		}
		href := strings.TrimSpace(hrefPart[:end])
		if href == "" {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil {
			continue
		}
		return base.ResolveReference(ref).String()
	}

	return base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String()
}

// ProbeDomain checks configured ports and schemes sequentially on a single domain.
func (p *Prober) ProbeDomain(ctx context.Context, domain string) []ProbeResult {
	var results []ProbeResult
	for _, port := range p.ports {
		for _, scheme := range schemesForPort(port) {
			select {
			case <-ctx.Done():
				return results
			default:
			}

			res := p.ProbeSingle(ctx, scheme, domain, port)
			if res != nil {
				results = append(results, *res)
				if scheme == "https" {
					break // skip HTTP if HTTPS resolved on non-standard port
				}
			}
		}
	}
	return results
}

// ProbeBatch runs scans concurrently across multiple domains.
func (p *Prober) ProbeBatch(ctx context.Context, domains []string) []ProbeResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []ProbeResult
	sem := make(chan struct{}, p.threads)

	var ticker *time.Ticker
	if p.rateLimit > 0 {
		interval := time.Second / time.Duration(p.rateLimit)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			break
		default:
		}

		if ticker != nil {
			<-ticker.C
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(dom string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			resList := p.ProbeDomain(ctx, dom)
			if len(resList) > 0 {
				mu.Lock()
				results = append(results, resList...)
				mu.Unlock()
			}
		}(domain)
	}

	wg.Wait()
	return results
}
