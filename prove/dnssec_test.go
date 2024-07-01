package prove

import (
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestParseDNSSECExt(t *testing.T) {
	tests := []struct {
		domain   string
		filename string
		expected string
	}{
		{"shakestation.", "valid_shakestation.hex", ""},
		{"shakestation", "valid_shakestation.hex", ""},
		{"shakestation", "valid_shakestation.hex", ""},
		{"subdomain.shakestation", "valid_shakestation.hex", "no TLSA record covers the domain subdomain.shakestation"},
		{"invaliddomain", "valid_shakestation.hex", "no TLSA record covers the domain invaliddomain"},
		{"hakestation", "valid_shakestation.hex", "no TLSA record covers the domain hakestation"},
		{"tcp.shakestation", "valid_shakestation.hex", "no TLSA record covers the domain tcp.shakestation"},
		{"_443._tcp.shakestation", "valid_shakestation.hex", "no TLSA record covers the domain _443._tcp.shakestation"},
		{"shakestation", "valid_test.lazydane.hex", "no TLSA record covers the domain shakestation"},
		{"test.lazydane", "valid_test.lazydane.hex", ""},
		{"tst.lazydane", "valid_test.lazydane.hex", "no TLSA record covers the domain tst.lazydane"},
		{"lazydane", "valid_test.lazydane.hex", "no TLSA record covers the domain lazydane"},
		{".lazydane", "valid_test.lazydane.hex", "no TLSA record covers the domain .lazydane"},
		{"shakestation", "invalid_shakestation.hex", "any"},
		{"netmeister.org", "invalid_netmeister.org.hex", ""},
		{"htools", "valid_wildcard_htools.hex", ""},
		{"htools", "invalid_wrong_data.hex", "any"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			filePath := filepath.Join("testdata", tt.filename)
			input, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("Failed to read test data file for domain %s, %s: %v", tt.domain, tt.filename, err)
			}
			val, err := hex.DecodeString(string(input))
			if err != nil {
				t.Fatalf("Failed to read hex data for domain %s file %s: %v", tt.domain, tt.filename, err)
			}

			records, err := ParseExt(val)
			if err != nil {
				if tt.expected == "any" {
					return
				}
				t.Fatalf("Failed to parse DNSSEC extension for domain %s: %v", tt.domain, err)
			}

			var tlsa *dns.TLSA
			var ok bool
			for _, record := range records {
				if record.Header().Rrtype == dns.TypeTLSA {
					tlsa, ok = record.(*dns.TLSA)
					if !ok {
						continue
					}
				}
			}
			if tlsa == nil {
				log.Print(records)
				t.Fatalf("no tlsa is found for domain %s", tt.domain)
			}

			err = VerifyDNSSECChain(val, tt.domain, tlsa)
			if tt.expected == "" {
				if err != nil {
					t.Fatalf("Expected nil error for domain %s, got %v", tt.domain, err)
				}
			} else if tt.expected == "any" {
				if err == nil {
					t.Fatalf("Expected error for domain %s, got nil", tt.domain)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected error for domain %s, got nil", tt.domain)
				} else if err.Error() != tt.expected {
					t.Fatalf("Expected error %s for domain %s, got %v", tt.expected, tt.domain, err)
				}
			}
		})
	}

}
