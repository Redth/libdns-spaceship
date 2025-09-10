// Package libdnsspaceship implements a DNS record management client compatible
// with the libdns interfaces for Spaceship. This package allows you to manage
// DNS records using the Spaceship DNS API.
package libdnsspaceship

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Spaceship.
type Provider struct {
	// APIKey is the Spaceship API key for authentication
	APIKey string `json:"api_key,omitempty"`

	// APISecret is the Spaceship API secret for authentication
	APISecret string `json:"api_secret,omitempty"`

	// BaseURL is the base URL for the Spaceship API (defaults to https://spaceship.dev/api)
	BaseURL string `json:"base_url,omitempty"`

	// HTTPClient allows customization of the HTTP client used for API requests
	HTTPClient *http.Client `json:"-"`

	// PageSize controls pagination size used by GetRecords (defaults to 100)
	PageSize int `json:"page_size,omitempty"`
}

// spaceshipRecord represents a DNS record in the Spaceship API format
type spaceshipRecord struct {
	Type string `json:"type"`
	Name string `json:"name"`
	TTL  int    `json:"ttl,omitempty"`
	// type-specific fields
	Address         string `json:"address,omitempty"`         // A, AAAA
	Cname           string `json:"cname,omitempty"`           // CNAME
	Value           string `json:"value,omitempty"`           // TXT and generic
	Exchange        string `json:"exchange,omitempty"`        // MX
	Preference      int    `json:"preference,omitempty"`      // MX
	Service         string `json:"service,omitempty"`         // SRV
	Protocol        string `json:"protocol,omitempty"`        // SRV
	Priority        int    `json:"priority,omitempty"`        // SRV
	Weight          int    `json:"weight,omitempty"`          // SRV
	Port            int    `json:"port,omitempty"`            // SRV (numeric)
	PortStr         string `json:"portStr,omitempty"`         // underscored port like "_8443" for SVCB/HTTPS
	Target          string `json:"target,omitempty"`          // SRV
	Nameserver      string `json:"nameserver,omitempty"`      // NS
	Pointer         string `json:"pointer,omitempty"`         // PTR
	Flag            int    `json:"flag,omitempty"`            // CAA
	Tag             string `json:"tag,omitempty"`             // CAA
	AssociationData string `json:"associationData,omitempty"` // TLSA
	Usage           int    `json:"usage,omitempty"`           // TLSA
	Selector        int    `json:"selector,omitempty"`        // TLSA
	Matching        int    `json:"matching,omitempty"`        // TLSA
	AliasName       string `json:"aliasName,omitempty"`       // ALIAS
	Scheme          string `json:"scheme,omitempty"`          // HTTPS/SVCB
	SvcPriority     int    `json:"svcPriority,omitempty"`     // HTTPS/SVCB
	TargetName      string `json:"targetName,omitempty"`      // HTTPS/SVCB
	SvcParams       string `json:"svcParams,omitempty"`       // HTTPS/SVCB
}

// listResponse models the GET /v1/dns/records/{domain} response
type listResponse struct {
	Items []spaceshipRecord `json:"items"`
	Total int               `json:"total"`
}

// getHTTPClient returns the HTTP client to use for API requests
func (p *Provider) getHTTPClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}

// getBaseURL returns the base URL for API requests
func (p *Provider) getBaseURL() string {
	if p.BaseURL != "" {
		return strings.TrimSuffix(p.BaseURL, "/")
	}
	// Default from the OpenAPI servers
	return "https://spaceship.dev/api"
}

// doRequest performs an HTTP request to the Spaceship API and returns response body and status code
func (p *Provider) doRequest(ctx context.Context, method, endpoint string, body interface{}) ([]byte, int, error) {
	url := p.getBaseURL() + endpoint
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Use API key/secret headers as described in the OpenAPI spec
	if p.APIKey != "" {
		req.Header.Set("X-API-Key", p.APIKey)
	}
	if p.APISecret != "" {
		req.Header.Set("X-API-Secret", p.APISecret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	client := p.getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return respBody, resp.StatusCode, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, resp.StatusCode, nil
}

// convertToLibdnsRecord converts a spaceship record to a libdns record
func (p *Provider) convertToLibdnsRecord(sr spaceshipRecord, zone string) libdns.Record {
	// Remove the zone from the name if it's present
	name := strings.TrimSuffix(sr.Name, "."+zone)
	name = strings.TrimSuffix(name, ".")
	// If the name equals the zone, it's the root record
	if name == zone || sr.Name == zone {
		name = ""
	}

	ttl := time.Duration(sr.TTL) * time.Second

	switch strings.ToUpper(sr.Type) {
	case "A", "AAAA":
		if sr.Address != "" {
			ip, err := netip.ParseAddr(sr.Address)
			if err == nil {
				return libdns.Address{
					Name:         name,
					TTL:          ttl,
					IP:           ip,
					ProviderData: sr,
				}
			}
		}
	case "TXT":
		return libdns.TXT{
			Name:         name,
			TTL:          ttl,
			Text:         sr.Value,
			ProviderData: sr,
		}
	case "CNAME":
		return libdns.CNAME{
			Name:         name,
			TTL:          ttl,
			Target:       sr.Cname,
			ProviderData: sr,
		}
	case "MX":
		return libdns.MX{
			Name:         name,
			TTL:          ttl,
			Target:       sr.Exchange,
			Preference:   uint16(sr.Preference),
			ProviderData: sr,
		}
	case "SRV":
		// Represent SRV as an RR with a common textual form: "priority weight port target"
		return libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: "SRV",
			Data: fmt.Sprintf("%d %d %d %s", sr.Priority, sr.Weight, sr.Port, sr.Target),
		}
	case "NS":
		return libdns.RR{Name: name, TTL: ttl, Type: "NS", Data: sr.Nameserver}
	case "PTR":
		return libdns.RR{Name: name, TTL: ttl, Type: "PTR", Data: sr.Pointer}
	case "CAA":
		return libdns.RR{Name: name, TTL: ttl, Type: "CAA", Data: fmt.Sprintf("%d %s %s", sr.Flag, sr.Tag, sr.Value)}
	case "TLSA":
		return libdns.RR{Name: name, TTL: ttl, Type: "TLSA", Data: fmt.Sprintf("%d %d %d %s", sr.Usage, sr.Selector, sr.Matching, sr.AssociationData)}
	case "HTTPS", "SVCB":
		// For HTTPS/SVCB we use targetName in Data when present; port may be underscored string or numeric
		port := sr.PortStr
		if port == "" && sr.Port != 0 {
			port = fmt.Sprintf("%d", sr.Port)
		}
		return libdns.RR{Name: name, TTL: ttl, Type: strings.ToUpper(sr.Type), Data: fmt.Sprintf("%s %s %d %s %s", port, sr.Scheme, sr.SvcPriority, sr.TargetName, sr.SvcParams)}
	}

	// Fallback to RR for unsupported or unparsed types
	return libdns.RR{
		Name: name,
		TTL:  ttl,
		Type: sr.Type,
		Data: func() string {
			// prefer the most likely field
			if sr.Value != "" {
				return sr.Value
			}
			if sr.Address != "" {
				return sr.Address
			}
			if sr.Cname != "" {
				return sr.Cname
			}
			if sr.Exchange != "" {
				return sr.Exchange
			}
			if sr.TargetName != "" {
				return sr.TargetName
			}
			return ""
		}(),
	}
}

// convertFromLibdnsRecord converts a libdns record to a spaceship record (create/update payload)
func (p *Provider) convertFromLibdnsRecord(lr libdns.Record, zone string) spaceshipRecord {
	rr := lr.RR()

	// Ensure the name includes the zone
	name := rr.Name
	if name != "" && !strings.HasSuffix(name, zone) {
		name = name + "." + zone
	}

	priority := 0

	rec := spaceshipRecord{
		Name: name,
		Type: strings.ToUpper(rr.Type),
		TTL:  int(rr.TTL.Seconds()),
	}

	// Extract priority for MX records
	if mx, ok := lr.(libdns.MX); ok {
		priority = int(mx.Preference)
		rec.Exchange = mx.Target
		rec.Preference = priority
		return rec
	}

	switch v := lr.(type) {
	case libdns.Address:
		rec.Address = v.IP.String()
	case libdns.TXT:
		rec.Value = v.Text
	case libdns.CNAME:
		rec.Cname = v.Target
	case libdns.MX:
		// handled above
	default:
		// generic RR: put the raw data into Value and leave specific fields empty
		rec.Value = rr.Data
		// attempt to parse common RR.Data formats for richer support
		switch strings.ToUpper(rr.Type) {
		case "SRV":
			// expected "priority weight port target"
			parts := strings.Fields(rr.Data)
			if len(parts) >= 4 {
				if v, err := strconv.Atoi(parts[0]); err == nil {
					rec.Priority = v
				}
				if v, err := strconv.Atoi(parts[1]); err == nil {
					rec.Weight = v
				}
				if v, err := strconv.Atoi(parts[2]); err == nil {
					rec.Port = v
				}
				rec.Target = strings.Join(parts[3:], " ")
			}
		case "CAA":
			// expected "flag tag value"
			parts := strings.Fields(rr.Data)
			if len(parts) >= 3 {
				if v, err := strconv.Atoi(parts[0]); err == nil {
					rec.Flag = v
				}
				rec.Tag = parts[1]
				rec.Value = strings.Join(parts[2:], " ")
			}
		case "TLSA":
			// expected "usage selector matching associationData"
			parts := strings.Fields(rr.Data)
			if len(parts) >= 4 {
				if v, err := strconv.Atoi(parts[0]); err == nil {
					rec.Usage = v
				}
				if v, err := strconv.Atoi(parts[1]); err == nil {
					rec.Selector = v
				}
				if v, err := strconv.Atoi(parts[2]); err == nil {
					rec.Matching = v
				}
				rec.AssociationData = strings.Join(parts[3:], " ")
			}
		case "HTTPS", "SVCB":
			// expected "port scheme svcPriority targetName svcParams"
			parts := strings.Fields(rr.Data)
			if len(parts) >= 4 {
				// port can be underscored or numeric; store in PortStr if not numeric
				p0 := parts[0]
				if v, err := strconv.Atoi(p0); err == nil {
					rec.Port = v
				} else {
					rec.PortStr = p0
				}
				rec.Scheme = parts[1]
				if v, err := strconv.Atoi(parts[2]); err == nil {
					rec.SvcPriority = v
				}
				if len(parts) >= 4 {
					rec.TargetName = parts[3]
				}
				if len(parts) >= 5 {
					rec.SvcParams = strings.Join(parts[4:], " ")
				}
			}
		case "NS":
			rec.Nameserver = rr.Data
		case "PTR":
			rec.Pointer = rr.Data
		}
	}

	return rec
}

// convertFromLibdnsRecordForDelete builds a ResourceRecordDeleteItem representation from libdns.Record
func (p *Provider) convertFromLibdnsRecordForDelete(lr libdns.Record, zone string) spaceshipRecord {
	rr := lr.RR()
	name := rr.Name
	if name == "" {
		name = "@"
	}
	// ensure full name
	if !strings.HasSuffix(name, zone) && name != "@" {
		name = name + "." + zone
	}

	rec := spaceshipRecord{
		Type: strings.ToUpper(rr.Type),
		Name: name,
	}

	switch v := lr.(type) {
	case libdns.Address:
		rec.Address = v.IP.String()
	case libdns.TXT:
		rec.Value = v.Text
	case libdns.CNAME:
		rec.Cname = v.Target
	case libdns.MX:
		rec.Exchange = v.Target
		rec.Preference = int(v.Preference)
	default:
		rec.Value = rr.Data
	}

	return rec
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if p.APIKey == "" || p.APISecret == "" {
		return nil, fmt.Errorf("API key and secret are required")
	}

	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")

	var records []libdns.Record
	// API requires pagination parameters 'take' and 'skip'. We'll page through all records.
	take := 100
	if p.PageSize > 0 {
		take = p.PageSize
	}
	skip := 0
	for {
		endpoint := fmt.Sprintf("/v1/dns/records/%s?take=%d&skip=%d", zone, take, skip)
		body, _, err := p.doRequest(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get records: %w", err)
		}
		var lr listResponse
		if err := json.Unmarshal(body, &lr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal records response: %w", err)
		}
		for _, sr := range lr.Items {
			records = append(records, p.convertToLibdnsRecord(sr, zone))
		}
		if len(records) >= lr.Total {
			break
		}
		skip += take
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.APIKey == "" || p.APISecret == "" {
		return nil, fmt.Errorf("API key and secret are required")
	}

	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")

	var items []spaceshipRecord
	for _, r := range records {
		items = append(items, p.convertFromLibdnsRecord(r, zone))
	}

	payload := map[string]interface{}{
		"force": false,
		"items": items,
	}

	endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
	_, status, err := p.doRequest(ctx, "PUT", endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to append records: %w", err)
	}
	if status != 204 {
		// In case API returns body with created data we could parse it; but it should be 204
		// Fall back to returning the input records
	}

	// Return records converted from the request payload as the representation of what was created
	var added []libdns.Record
	for _, it := range items {
		added = append(added, p.convertToLibdnsRecord(it, zone))
	}
	return added, nil
}

// SetRecords sets the records in the zone by saving the provided records (force update).
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.APIKey == "" || p.APISecret == "" {
		return nil, fmt.Errorf("API key and secret are required")
	}

	zone = strings.TrimSuffix(zone, ".")
	var items []spaceshipRecord
	for _, r := range records {
		items = append(items, p.convertFromLibdnsRecord(r, zone))
	}
	payload := map[string]interface{}{
		"force": true,
		"items": items,
	}
	endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
	_, status, err := p.doRequest(ctx, "PUT", endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to set records: %w", err)
	}
	if status != 204 {
		// API should return 204. If not, still return input records as best-effort.
	}
	var updated []libdns.Record
	for _, it := range items {
		updated = append(updated, p.convertToLibdnsRecord(it, zone))
	}
	return updated, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.APIKey == "" || p.APISecret == "" {
		return nil, fmt.Errorf("API key and secret are required")
	}

	zone = strings.TrimSuffix(zone, ".")
	var items []spaceshipRecord
	for _, rec := range records {
		// If the concrete libdns type carries ProviderData with the original spaceshipRecord,
		// prefer using that exact payload to delete the record (avoids mismatches).
		var item spaceshipRecord
		switch r := rec.(type) {
		case libdns.Address:
			if pd, ok := r.ProviderData.(spaceshipRecord); ok {
				item = pd
			} else {
				item = p.convertFromLibdnsRecordForDelete(rec, zone)
			}
		case libdns.TXT:
			if pd, ok := r.ProviderData.(spaceshipRecord); ok {
				item = pd
			} else {
				item = p.convertFromLibdnsRecordForDelete(rec, zone)
			}
		case libdns.CNAME:
			if pd, ok := r.ProviderData.(spaceshipRecord); ok {
				item = pd
			} else {
				item = p.convertFromLibdnsRecordForDelete(rec, zone)
			}
		case libdns.MX:
			if pd, ok := r.ProviderData.(spaceshipRecord); ok {
				item = pd
			} else {
				item = p.convertFromLibdnsRecordForDelete(rec, zone)
			}
		default:
			item = p.convertFromLibdnsRecordForDelete(rec, zone)
		}
		items = append(items, item)
	}
	endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
	_, status, err := p.doRequest(ctx, "DELETE", endpoint, items)
	if err != nil {
		return nil, fmt.Errorf("failed to delete records: %w", err)
	}
	if status != 204 {
		// API should return 204. If not, proceed anyway.
	}
	return records, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
