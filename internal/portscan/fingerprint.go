package portscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	openSSHVersionPattern = regexp.MustCompile(`(?i)openssh[_-]([0-9.]+)`)
	serverVersionPattern  = regexp.MustCompile(`(?i)(nginx|apache|caddy|iis|envoy|haproxy)[ /-]?([0-9.]+)?`)
)

var serviceBannerHints = []struct {
	needle  string
	service string
	product string
}{
	{"openresty", "http", "OpenResty"},
	{"litespeed", "http", "LiteSpeed"},
	{"microsoft-iis", "http", "IIS"},
	{"iis/", "http", "IIS"},
	{"varnish", "http", "Varnish"},
	{"haproxy", "http", "HAProxy"},
	{"envoy", "http", "Envoy"},
	{"jetty", "http", "Jetty"},
	{"tomcat", "http", "Tomcat"},
	{"jboss", "http", "JBoss"},
	{"kestrel", "http", "Kestrel"},
	{"gunicorn", "http", "Gunicorn"},
	{"uvicorn", "http", "Uvicorn"},
	{"postfix", "smtp", "Postfix"},
	{"exim", "smtp", "Exim"},
	{"vsftpd", "ftp", "vsFTPd"},
	{"pure-ftpd", "ftp", "Pure-FTPd"},
	{"proftpd", "ftp", "ProFTPD"},
	{"redis", "redis", "Redis"},
	{"memcached", "memcached", "Memcached"},
	{"mongodb", "mongodb", "MongoDB"},
	{"elasticsearch", "http", "Elasticsearch"},
	{"kafka", "kafka", "Kafka"},
	{"rabbitmq", "amqp", "RabbitMQ"},
}

// BannerFingerprint stores protocol hints extracted from a live connection.
type BannerFingerprint struct {
	Banner  string
	Service string
	Product string
	Version string
}

// GrabBanner attempts to extract service banners from open sockets.
// If the protocol isn't a "server-speaks-first" type, it sends protocol-specific probes.
func GrabBanner(conn net.Conn, host string, port int, timeout time.Duration) BannerFingerprint {
	if isTLSPort(port) {
		if fp, ok := probeHTTPS(conn, host, port, timeout); ok {
			return fp
		}
		return BannerFingerprint{Service: "https"}
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	type readResult struct {
		text string
		err  error
	}
	ch := make(chan readResult, 1)

	go func() {
		buf := make([]byte, 512)
		n, err := reader.Read(buf)
		if n > 0 {
			ch <- readResult{text: string(buf[:n]), err: nil}
		} else {
			ch <- readResult{text: "", err: err}
		}
	}()

	select {
	case res := <-ch:
		if res.err == nil && res.text != "" {
			return fingerprintFromBanner(port, strings.TrimSpace(res.text))
		}
	case <-time.After(400 * time.Millisecond):
		// No banner read, proceed to write probe payload
	}

	var probe []byte
	switch port {
	case 80, 8080, 8000, 3000, 5000:
		probe = []byte(fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host))
	case 6379:
		probe = []byte("PING\r\n")
	case 11211:
		probe = []byte("stats\r\n")
	case 25, 587:
		probe = []byte("EHLO nullfinder.local\r\n")
	default:
		probe = []byte("\r\n\r\n")
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err := conn.Write(probe)
	if err != nil {
		return BannerFingerprint{}
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return BannerFingerprint{}
	}

	return fingerprintFromBanner(port, strings.TrimSpace(string(buf[:n])))
}

// IdentifyService maps banners or port numbers to clean service identifiers.
func IdentifyService(port int, banner string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "ssh-") {
		return "ssh"
	}
	for _, hint := range serviceBannerHints {
		if strings.Contains(bannerLower, hint.needle) {
			return hint.service
		}
	}
	if strings.Contains(bannerLower, "ftp") || (strings.HasPrefix(banner, "220") && strings.Contains(bannerLower, "ftp")) {
		return "ftp"
	}
	if strings.Contains(bannerLower, "smtp") || (strings.HasPrefix(banner, "220") && (strings.Contains(bannerLower, "mail") || strings.Contains(bannerLower, "smtp"))) {
		return "smtp"
	}
	if strings.Contains(bannerLower, "http/") || strings.Contains(bannerLower, "html") {
		if port == 443 || port == 8443 {
			return "https"
		}
		return "http"
	}
	if strings.Contains(bannerLower, "pong") || strings.Contains(bannerLower, "noauth") {
		return "redis"
	}
	if strings.Contains(bannerLower, "stat ") || strings.Contains(bannerLower, "version ") {
		return "memcached"
	}
	if strings.Contains(bannerLower, "mysql") || strings.Contains(bannerLower, "mariadb") {
		return "mysql"
	}
	if strings.Contains(bannerLower, "postgresql") || strings.Contains(bannerLower, "postgres") {
		return "postgresql"
	}
	if strings.Contains(bannerLower, "amqp") || strings.Contains(bannerLower, "rabbitmq") {
		return "amqp"
	}

	// Port guesses
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80, 8080, 8000, 3000, 5000:
		return "http"
	case 443, 8443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	}

	return "unknown"
}

// ExtractProductVersion derives a product and version hint from a service banner.
func ExtractProductVersion(service string, banner string) (string, string) {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "openssh") {
		match := openSSHVersionPattern.FindStringSubmatch(banner)
		if len(match) > 1 {
			return "OpenSSH", match[1]
		}
		return "OpenSSH", ""
	}

	for _, hint := range serviceBannerHints {
		if strings.Contains(bannerLower, hint.needle) && hint.product != "" {
			return hint.product, ""
		}
	}

	if match := serverVersionPattern.FindStringSubmatch(banner); len(match) > 0 {
		product := strings.ToLower(match[1])
		if product != "" {
			product = strings.ToUpper(product[:1]) + product[1:]
		}
		version := ""
		if len(match) > 2 {
			version = match[2]
		}
		return product, version
	}

	switch service {
	case "ssh":
		return "SSH", ""
	case "redis":
		return "Redis", ""
	case "memcached":
		return "Memcached", ""
	case "mysql":
		return "MySQL", ""
	case "postgresql":
		return "PostgreSQL", ""
	case "ftp":
		return "FTP", ""
	case "smtp":
		return "SMTP", ""
	case "http":
		return "HTTP", ""
	case "https":
		return "HTTPS", ""
	}

	return "", ""
}

func fingerprintFromBanner(port int, banner string) BannerFingerprint {
	service := IdentifyService(port, banner)
	product, version := ExtractProductVersion(service, banner)
	return BannerFingerprint{
		Banner:  banner,
		Service: service,
		Product: product,
		Version: version,
	}
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443:
		return true
	default:
		return false
	}
}

func probeHTTPS(conn net.Conn, host string, port int, timeout time.Duration) (BannerFingerprint, bool) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	tlsConn := tls.Client(conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return BannerFingerprint{}, false
	}

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return BannerFingerprint{Service: "https"}, true
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return BannerFingerprint{Service: "https"}, true
	}
	defer resp.Body.Close()

	banner := resp.Proto + " " + resp.Status
	if server := resp.Header.Get("Server"); server != "" {
		banner += "\r\nServer: " + server
	}
	product, version := ExtractProductVersion("https", banner)

	return BannerFingerprint{
		Banner:  strings.TrimSpace(banner),
		Service: "https",
		Product: product,
		Version: version,
	}, true
}
