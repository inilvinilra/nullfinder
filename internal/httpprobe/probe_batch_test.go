package httpprobe

import (
	"reflect"
	"testing"
)

func TestSchemesForPort(t *testing.T) {
	tests := []struct {
		port int
		want []string
	}{
		{port: 80, want: []string{"http"}},
		{port: 443, want: []string{"https"}},
		{port: 8080, want: []string{"http", "https"}},
		{port: 8443, want: []string{"https", "http"}},
		{port: 9000, want: []string{"http", "https"}},
	}

	for _, tc := range tests {
		got := schemesForPort(tc.port)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("schemesForPort(%d) = %v; want %v", tc.port, got, tc.want)
		}
	}
}
