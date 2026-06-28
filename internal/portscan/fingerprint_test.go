package portscan

import "testing"

func TestIdentifyService(t *testing.T) {
	tests := []struct {
		port     int
		banner   string
		expected string
	}{
		{22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "ssh"},
		{21, "220 vsFTPd 3.0.3", "ftp"},
		{25, "220 mail.example.com ESMTP Postfix", "smtp"},
		{80, "HTTP/1.1 200 OK\r\nServer: nginx", "http"},
		{443, "HTTP/1.1 403 Forbidden", "https"},
		{8080, "HTTP/1.1 200 OK\r\nServer: openresty/1.25.3.1", "http"},
		{6379, "+PONG", "redis"},
		{6379, "-NOAUTH Authentication required", "redis"},
		{5672, "AMQP 0-9-1\r\nproduct: RabbitMQ", "amqp"},
		{3306, "", "mysql"},
		{5432, "", "postgresql"},
		{9999, "", "unknown"},
	}

	for _, tc := range tests {
		actual := IdentifyService(tc.port, tc.banner)
		if actual != tc.expected {
			t.Errorf("IdentifyService(%d, %q) = %q; want %q", tc.port, tc.banner, actual, tc.expected)
		}
	}
}

func TestExtractProductVersion(t *testing.T) {
	tests := []struct {
		service         string
		banner          string
		expectedProduct string
		expectedVersion string
	}{
		{"ssh", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH", "8.2"},
		{"http", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", "Nginx", "1.24.0"},
		{"https", "HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.58", "Apache", "2.4.58"},
		{"http", "HTTP/1.1 200 OK\r\nServer: openresty/1.25.3.1", "OpenResty", ""},
		{"redis", "+PONG", "Redis", ""},
	}

	for _, tc := range tests {
		product, version := ExtractProductVersion(tc.service, tc.banner)
		if product != tc.expectedProduct || version != tc.expectedVersion {
			t.Errorf("ExtractProductVersion(%q, %q) = (%q, %q); want (%q, %q)", tc.service, tc.banner, product, version, tc.expectedProduct, tc.expectedVersion)
		}
	}
}
