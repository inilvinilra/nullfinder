package portscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestPortScannerScanSingle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-MockSSH\n"))
			_ = conn.Close()
		}
	}()

	scanner := NewPortScanner(1, 0, 1)
	res := scanner.ScanSingle(context.Background(), ScanTarget{Domain: host, Address: host}, port)

	if res == nil {
		t.Fatalf("expected result, got nil")
	}

	if res.State != "open" {
		t.Errorf("expected state to be 'open', got %q", res.State)
	}

	if res.Service != "ssh" {
		t.Errorf("expected service to be 'ssh', got %q", res.Service)
	}

	if res.Address != host {
		t.Errorf("expected address to be %q, got %q", host, res.Address)
	}

	if res.Product != "SSH" {
		t.Errorf("expected product to be 'SSH', got %q", res.Product)
	}

	if !strings.Contains(res.Banner, "SSH-2.0-MockSSH") {
		t.Errorf("expected banner to contain 'SSH-2.0-MockSSH', got %q", res.Banner)
	}
}

func TestClassifyDialError(t *testing.T) {
	state, reason := classifyDialError(context.DeadlineExceeded)
	if state != "filtered" || reason == "" {
		t.Fatalf("expected deadline to map to filtered, got state=%q reason=%q", state, reason)
	}
}
