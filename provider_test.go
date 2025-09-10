package libdnsspaceship

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// helper roundTripper for testing HTTP client behavior
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProvider_GetRecords_NoAuth(t *testing.T) {
	provider := &Provider{}
	_, err := provider.GetRecords(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "API key and secret are required") {
		t.Errorf("Expected API key/secret error, got: %v", err)
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
				Name:    "test.example.com",
				Type:    "A",
				Address: "192.0.2.1",
				TTL:     300,
			},
			expected: "libdns.Address",
		},
		{
			name: "TXT record",
			input: spaceshipRecord{
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
				Name:  "www.example.com",
				Type:  "CNAME",
				Cname: "example.com",
				TTL:   300,
			},
			expected: "libdns.CNAME",
		},
		{
			name: "MX record",
			input: spaceshipRecord{
				Name:       "example.com",
				Type:       "MX",
				Exchange:   "mail.example.com",
				TTL:        300,
				Preference: 10,
			},
			expected: "libdns.MX",
		},
		{
			name: "SRV record",
			input: spaceshipRecord{
				Name:     "_sip._tcp.example.com",
				Type:     "SRV",
				Priority: 10,
				Weight:   20,
				Port:     5060,
				Target:   "sip.example.com",
				TTL:      3600,
			},
			expected: "libdns.RR",
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
			case "libdns.RR":
				if _, ok := result.(libdns.RR); !ok {
					t.Errorf("Expected libdns.RR, got %T", result)
				}
			}

			// Verify the record has the correct name (should have zone stripped)
			rr := result.RR()
			expectedNames := map[string]string{
				"A record":     "test",
				"TXT record":   "test",
				"CNAME record": "www",
				"MX record":    "",
				"SRV record":   "_sip._tcp",
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
	if result.Address != "192.0.2.1" {
		t.Errorf("Expected address 192.0.2.1, got %s", result.Address)
	}
	if result.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", result.TTL)
	}
}

func TestDoRequest_HeadersAndBody(t *testing.T) {
	provider := &Provider{
		APIKey:    "K",
		APISecret: "S",
	}

	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// verify headers
			if req.Header.Get("X-API-Key") != "K" {
				t.Fatalf("missing X-API-Key")
			}
			if req.Header.Get("X-API-Secret") != "S" {
				t.Fatalf("missing X-API-Secret")
			}
			// read body and return it back
			b, _ := io.ReadAll(req.Body)
			res := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}
			return res, nil
		}),
	}

	body := map[string]string{"hello": "world"}
	respBody, status, err := provider.doRequest(context.Background(), "POST", "/test", body)
	if err != nil {
		t.Fatalf("doRequest failed: %v", err)
	}
	if status != 200 {
		t.Fatalf("unexpected status: %d", status)
	}
	if string(respBody) != "{\"hello\":\"world\"}" {
		t.Fatalf("unexpected body: %s", string(respBody))
	}
}

func TestGetRecords_Pagination(t *testing.T) {
	provider := &Provider{
		APIKey:    "K",
		APISecret: "S",
		PageSize:  2,
	}

	// Create two pages: first returns 2 items, total 3; second returns 1 item.
	pageCount := 0
	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			pageCount++
			if pageCount == 1 {
				json := `{"items":[{"type":"A","name":"test","address":"1.1.1.1","ttl":300},{"type":"A","name":"more","address":"1.1.1.2","ttl":300}],"total":3}`
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(json))}, nil
			}
			json := `{"items":[{"type":"A","name":"other","address":"1.1.1.3","ttl":300}],"total":3}`
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(json))}, nil
		}),
	}

	recs, err := provider.GetRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recs))
	}
}

func TestConvertToLibdnsRecord_ExtendedTypes(t *testing.T) {
	provider := &Provider{}
	zone := "example.com"

	// SRV
	srv := spaceshipRecord{Type: "SRV", Name: "_sip._tcp.example.com", Priority: 10, Weight: 20, Port: 5060, Target: "sip.example.com", TTL: 3600}
	rr := provider.convertToLibdnsRecord(srv, zone)
	if r, ok := rr.(libdns.RR); !ok || r.Type != "SRV" || r.Data != "10 20 5060 sip.example.com" {
		t.Fatalf("unexpected SRV conversion: %#v", rr)
	}

	// NS
	ns := spaceshipRecord{Type: "NS", Name: "example.com", Nameserver: "ns1.example.com", TTL: 3600}
	rr = provider.convertToLibdnsRecord(ns, zone)
	if r, ok := rr.(libdns.RR); !ok || r.Type != "NS" || r.Data != "ns1.example.com" {
		t.Fatalf("unexpected NS conversion: %#v", rr)
	}

	// PTR
	ptr := spaceshipRecord{Type: "PTR", Name: "1.1.1.in-addr.arpa", Pointer: "host.example.com", TTL: 3600}
	rr = provider.convertToLibdnsRecord(ptr, zone)
	if r, ok := rr.(libdns.RR); !ok || r.Type != "PTR" || r.Data != "host.example.com" {
		t.Fatalf("unexpected PTR conversion: %#v", rr)
	}

	// CAA
	caa := spaceshipRecord{Type: "CAA", Name: "example.com", Flag: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600}
	rr = provider.convertToLibdnsRecord(caa, zone)
	if r, ok := rr.(libdns.RR); !ok || r.Type != "CAA" || r.Data != "0 issue letsencrypt.org" {
		t.Fatalf("unexpected CAA conversion: %#v", rr)
	}

	// TLSA
	tlsa := spaceshipRecord{Type: "TLSA", Name: "_443._tcp.example.com", Usage: 2, Selector: 1, Matching: 1, AssociationData: "7f83...", TTL: 3600}
	rr = provider.convertToLibdnsRecord(tlsa, zone)
	if r, ok := rr.(libdns.RR); !ok || r.Type != "TLSA" || !strings.Contains(r.Data, "7f83") {
		t.Fatalf("unexpected TLSA conversion: %#v", rr)
	}
}

func TestConvertFromLibdnsRecord_ParseRRData(t *testing.T) {
	provider := &Provider{}
	zone := "example.com"

	// SRV
	rr := libdns.RR{Name: "_sip._tcp", TTL: 3600 * time.Second, Type: "SRV", Data: "10 20 5060 sip.example.com"}
	rec := provider.convertFromLibdnsRecord(rr, zone)
	if rec.Priority != 10 || rec.Weight != 20 || rec.Port != 5060 || rec.Target != "sip.example.com" {
		t.Fatalf("SRV parsing failed: %#v", rec)
	}

	// TLSA
	rr = libdns.RR{Name: "_443._tcp", TTL: 3600 * time.Second, Type: "TLSA", Data: "2 1 1 7f83b165"}
	rec = provider.convertFromLibdnsRecord(rr, zone)
	if rec.Usage != 2 || rec.Selector != 1 || rec.Matching != 1 || rec.AssociationData != "7f83b165" {
		t.Fatalf("TLSA parsing failed: %#v", rec)
	}

	// HTTPS
	rr = libdns.RR{Name: "_443._https", TTL: 3600 * time.Second, Type: "HTTPS", Data: "_8443 _https 1 _443._https.www.example.com "}
	rec = provider.convertFromLibdnsRecord(rr, zone)
	if rec.PortStr != "_8443" || rec.Scheme != "_https" || rec.SvcPriority != 1 || rec.TargetName != "_443._https.www.example.com" {
		t.Fatalf("HTTPS parsing failed: %#v", rec)
	}

	// CAA
	rr = libdns.RR{Name: "example.com", TTL: 3600 * time.Second, Type: "CAA", Data: "0 issue letsencrypt.org"}
	rec = provider.convertFromLibdnsRecord(rr, zone)
	if rec.Flag != 0 || rec.Tag != "issue" || rec.Value != "letsencrypt.org" {
		t.Fatalf("CAA parsing failed: %#v", rec)
	}

	// NS
	rr = libdns.RR{Name: "example.com", TTL: 3600 * time.Second, Type: "NS", Data: "ns1.example.com"}
	rec = provider.convertFromLibdnsRecord(rr, zone)
	if rec.Nameserver != "ns1.example.com" {
		t.Fatalf("NS parsing failed: %#v", rec)
	}

	// PTR
	rr = libdns.RR{Name: "1.1.1.in-addr.arpa", TTL: 3600 * time.Second, Type: "PTR", Data: "host.example.com"}
	rec = provider.convertFromLibdnsRecord(rr, zone)
	if rec.Pointer != "host.example.com" {
		t.Fatalf("PTR parsing failed: %#v", rec)
	}
}

func TestRoundTrip_CreateListDelete(t *testing.T) {
	zone := "example.com"
	provider := &Provider{
		APIKey:    "K",
		APISecret: "S",
		PageSize:  100,
	}

	// in-memory store of spaceshipRecord representing the server state
	var store []spaceshipRecord
	// mutex not required for single-threaded test

	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			// unify path: look for "/v1/dns/records/"
			if !strings.Contains(path, "/v1/dns/records/") {
				return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found"))}, nil
			}
			if req.Method == "PUT" {
				var payload struct {
					Force bool              `json:"force"`
					Items []spaceshipRecord `json:"items"`
				}
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &payload)
				if payload.Force {
					// replace entire store
					store = payload.Items
				} else {
					store = append(store, payload.Items...)
				}
				return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			if req.Method == "GET" {
				q := req.URL.Query()
				take := 100
				if q.Get("take") != "" {
					if v, err := strconv.Atoi(q.Get("take")); err == nil {
						take = v
					}
				}
				skip := 0
				if q.Get("skip") != "" {
					if v, err := strconv.Atoi(q.Get("skip")); err == nil {
						skip = v
					}
				}
				end := skip + take
				if end > len(store) {
					end = len(store)
				}
				resp := listResponse{Items: store[skip:end], Total: len(store)}
				b, _ := json.Marshal(resp)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
			}
			if req.Method == "DELETE" {
				// delete items present in body
				var items []spaceshipRecord
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &items)
				// filter store: remove any item that matches a delete item on required fields
				newStore := make([]spaceshipRecord, 0, len(store))
				for _, existing := range store {
					keep := true
					for _, del := range items {
						if existing.Type == del.Type && existing.Name == del.Name {
							// for typed fields try matching identifying fields
							match := true
							switch strings.ToUpper(del.Type) {
							case "A":
								if del.Address != existing.Address {
									match = false
								}
							case "TXT":
								if del.Value != existing.Value {
									match = false
								}
							case "CNAME":
								if del.Cname != existing.Cname {
									match = false
								}
							case "MX":
								if del.Exchange != existing.Exchange || del.Preference != existing.Preference {
									match = false
								}
							default:
								// fallback: compare Value or Data-ish fields
								if del.Value != "" && del.Value != existing.Value {
									match = false
								}
							}
							if match {
								keep = false
								break
							}
						}
					}
					if keep {
						newStore = append(newStore, existing)
					}
				}
				store = newStore
				return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: 405, Body: io.NopCloser(strings.NewReader("method not allowed"))}, nil
		}),
	}

	// create some records with AppendRecords
	recsToAdd := []libdns.Record{
		libdns.Address{Name: "test", TTL: 300 * time.Second, IP: netip.MustParseAddr("1.1.1.1")},
		libdns.TXT{Name: "test", TTL: 300 * time.Second, Text: "hello"},
	}

	added, err := provider.AppendRecords(context.Background(), zone, recsToAdd)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if len(added) != len(recsToAdd) {
		t.Fatalf("expected %d added, got %d", len(recsToAdd), len(added))
	}

	// list records
	listed, err := provider.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 listed, got %d", len(listed))
	}

	// delete first
	_, err = provider.DeleteRecords(context.Background(), zone, []libdns.Record{listed[0]})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	// list again
	listed2, err := provider.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(listed2) != 1 {
		t.Fatalf("expected 1 listed after delete, got %d", len(listed2))
	}
}
