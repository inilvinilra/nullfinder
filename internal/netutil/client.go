package netutil

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetHTTPClient returns an HTTP client that resolves domain names using the provided list of DNS resolvers.
func GetHTTPClient(resolvers []string, timeout time.Duration, skipTLS bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	if len(resolvers) > 0 {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Select a resolver IP randomly to balance load
				ip := resolvers[rand.Intn(len(resolvers))]
				if !strings.Contains(ip, ":") {
					ip = ip + ":53"
				}
				d := net.Dialer{
					Timeout: timeout,
				}
				return d.DialContext(ctx, network, ip)
			},
		}
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLS,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
