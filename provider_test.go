package libdnsspaceship

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestProvider_GetRecords(t *testing.T) {
	provider := &Provider{
		APIToken: "test-token",
	}

	// This would normally make an API call, but since we don't have a real API
	// endpoint, we'll just test that it handles the missing token properly
	provider.APIToken = ""
	_, err := provider.GetRecords(context.Background(), "example.com")
	if err == nil || err.Error() != "API token is required" {
		t.Errorf("Expected API token error, got: %v", err)
	}
}

func TestProvider_ConvertToLibdnsRecord(t *testing.T) {
	provider := &Provider{}
	zone := "example.com"

	tests := []struct {
		name     string
		input    spaceshipRecord
		expected string // expected type
	}{
		{
			name: "A record",
			input: spaceshipRecord{
				ID:    "123",
				Name:  "test.example.com",
				Type:  "A",
				Value: "192.0.2.1",
				TTL:   300,
			},
			expected: "libdns.Address",
		},
		{
			name: "TXT record", 
			input: spaceshipRecord{
				ID:    "124",
				Name:  "test.example.com",
				Type:  "TXT",
				Value: "v=spf1 include:_spf.example.com ~all",
				TTL:   300,
			},
			expected: "libdns.TXT",
		},
		{
			name: "CNAME record",
			input: spaceshipRecord{
				ID:    "125",
				Name:  "www.example.com",
				Type:  "CNAME",
				Value: "example.com",
				TTL:   300,
			},
			expected: "libdns.CNAME",
		},
		{
			name: "MX record",
			input: spaceshipRecord{
				ID:       "126",
				Name:     "example.com",
				Type:     "MX",
				Value:    "mail.example.com",
				TTL:      300,
				Priority: 10,
			},
			expected: "libdns.MX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.convertToLibdnsRecord(tt.input, zone)
			
			switch tt.expected {
			case "libdns.Address":
				if _, ok := result.(libdns.Address); !ok {
					t.Errorf("Expected libdns.Address, got %T", result)
				}
			case "libdns.TXT":
				if _, ok := result.(libdns.TXT); !ok {
					t.Errorf("Expected libdns.TXT, got %T", result)
				}
			case "libdns.CNAME":
				if _, ok := result.(libdns.CNAME); !ok {
					t.Errorf("Expected libdns.CNAME, got %T", result)
				}
			case "libdns.MX":
				if _, ok := result.(libdns.MX); !ok {
					t.Errorf("Expected libdns.MX, got %T", result)
				}
			}

			// Verify the record has the correct name (should have zone stripped)
			rr := result.RR()
			expectedNames := map[string]string{
				"A record":     "test",
				"TXT record":   "test", 
				"CNAME record": "www",
				"MX record":    "", // Root domain should be empty
			}
			if expectedName := expectedNames[tt.name]; rr.Name != expectedName {
				t.Errorf("Expected name %q, got %q", expectedName, rr.Name)
			}
		})
	}
}

func TestProvider_ConvertFromLibdnsRecord(t *testing.T) {
	provider := &Provider{}
	zone := "example.com"

	// Test Address record
	addr := libdns.Address{
		Name: "test",
		TTL:  300 * time.Second,
		IP:   netip.MustParseAddr("192.0.2.1"),
	}

	result := provider.convertFromLibdnsRecord(addr, zone)
	if result.Name != "test.example.com" {
		t.Errorf("Expected full name, got %s", result.Name)
	}
	if result.Type != "A" {
		t.Errorf("Expected type A, got %s", result.Type)
	}
	if result.Value != "192.0.2.1" {
		t.Errorf("Expected value 192.0.2.1, got %s", result.Value)
	}
	if result.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", result.TTL)
	}
}