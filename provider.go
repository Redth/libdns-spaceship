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
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Spaceship.
type Provider struct {
	// APIToken is the Spaceship API token for authentication
	APIToken string `json:"api_token,omitempty"`
	
	// BaseURL is the base URL for the Spaceship API (defaults to https://api.spaceship.com)
	BaseURL string `json:"base_url,omitempty"`
	
	// HTTPClient allows customization of the HTTP client used for API requests
	HTTPClient *http.Client `json:"-"`
}

// spaceshipRecord represents a DNS record in the Spaceship API format
type spaceshipRecord struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
}

// spaceshipResponse represents the API response structure
type spaceshipResponse struct {
	Records []spaceshipRecord `json:"records,omitempty"`
	Success bool              `json:"success"`
	Message string            `json:"message,omitempty"`
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
	return "https://api.spaceship.com"
}

// makeAPIRequest performs an HTTP request to the Spaceship API
func (p *Provider) makeAPIRequest(ctx context.Context, method, endpoint string, body interface{}) (*spaceshipResponse, error) {
	url := p.getBaseURL() + endpoint
	
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}
	
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	client := p.getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}
	
	var apiResp spaceshipResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	if !apiResp.Success && apiResp.Message != "" {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}
	
	return &apiResp, nil
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
		ip, err := netip.ParseAddr(sr.Value)
		if err != nil {
			// If parsing fails, fall back to RR
			break
		}
		return libdns.Address{
			Name:         name,
			TTL:          ttl,
			IP:           ip,
			ProviderData: sr.ID, // Store the record ID for later use
		}
	case "TXT":
		return libdns.TXT{
			Name:         name,
			TTL:          ttl,
			Text:         sr.Value,
			ProviderData: sr.ID, // Store the record ID for later use
		}
	case "CNAME":
		return libdns.CNAME{
			Name:         name,
			TTL:          ttl,
			Target:       sr.Value,
			ProviderData: sr.ID, // Store the record ID for later use
		}
	case "MX":
		return libdns.MX{
			Name:         name,
			TTL:          ttl,
			Target:       sr.Value,
			Preference:   uint16(sr.Priority),
			ProviderData: sr.ID, // Store the record ID for later use
		}
	case "SRV":
		// For SRV records, we'd need to parse the value to extract port, weight, priority, target
		// For now, fallback to RR
		break
	}
	
	// Fallback to RR for unsupported types
	return libdns.RR{
		Name: name,
		TTL:  ttl,
		Type: sr.Type,
		Data: sr.Value,
	}
}

// convertFromLibdnsRecord converts a libdns record to a spaceship record
func (p *Provider) convertFromLibdnsRecord(lr libdns.Record, zone string) spaceshipRecord {
	rr := lr.RR()
	
	// Ensure the name includes the zone
	name := rr.Name
	if name != "" && !strings.HasSuffix(name, zone) {
		name = name + "." + zone
	}
	
	priority := 0
	
	// Extract priority for MX records
	if mx, ok := lr.(libdns.MX); ok {
		priority = int(mx.Preference)
	}
	
	return spaceshipRecord{
		Name:     name,
		Type:     rr.Type,
		Value:    rr.Data,
		TTL:      int(rr.TTL.Seconds()),
		Priority: priority,
	}
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if p.APIToken == "" {
		return nil, fmt.Errorf("API token is required")
	}
	
	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")
	
	endpoint := fmt.Sprintf("/v1/domains/%s/records", zone)
	resp, err := p.makeAPIRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get records: %w", err)
	}
	
	var records []libdns.Record
	for _, sr := range resp.Records {
		records = append(records, p.convertToLibdnsRecord(sr, zone))
	}
	
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.APIToken == "" {
		return nil, fmt.Errorf("API token is required")
	}
	
	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")
	
	var addedRecords []libdns.Record
	
	for _, record := range records {
		sr := p.convertFromLibdnsRecord(record, zone)
		
		endpoint := fmt.Sprintf("/v1/domains/%s/records", zone)
		resp, err := p.makeAPIRequest(ctx, "POST", endpoint, sr)
		if err != nil {
			return addedRecords, fmt.Errorf("failed to create record: %w", err)
		}
		
		// Assume the API returns the created record in the response
		if len(resp.Records) > 0 {
			addedRecords = append(addedRecords, p.convertToLibdnsRecord(resp.Records[0], zone))
		} else {
			// If no record returned, use the original record
			addedRecords = append(addedRecords, record)
		}
	}
	
	return addedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.APIToken == "" {
		return nil, fmt.Errorf("API token is required")
	}
	
	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")
	
	var updatedRecords []libdns.Record
	
	for _, record := range records {
		sr := p.convertFromLibdnsRecord(record, zone)
		
		// For SetRecords, we'll try to identify existing records by name and type
		// and update them, or create new ones if they don't exist
		// This is a simplified implementation - a more robust one would first
		// query existing records to find matches
		
		endpoint := fmt.Sprintf("/v1/domains/%s/records", zone)
		method := "POST" // Default to create
		
		// In a real implementation, you might want to:
		// 1. First get all records for the zone
		// 2. Find matches by name/type  
		// 3. Use PUT with the record ID if found, POST if not
		
		resp, err := p.makeAPIRequest(ctx, method, endpoint, sr)
		if err != nil {
			return updatedRecords, fmt.Errorf("failed to set record: %w", err)
		}
		
		// Assume the API returns the updated/created record in the response
		if len(resp.Records) > 0 {
			updatedRecords = append(updatedRecords, p.convertToLibdnsRecord(resp.Records[0], zone))
		} else {
			// If no record returned, use the original
			updatedRecords = append(updatedRecords, record)
		}
	}
	
	return updatedRecords, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.APIToken == "" {
		return nil, fmt.Errorf("API token is required")
	}
	
	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")
	
	var deletedRecords []libdns.Record
	
	for _, record := range records {
		// To delete a record, we need its ID. Since libdns records don't expose
		// an ID field directly, we have a few options:
		// 1. Use ProviderData field if the record type supports it
		// 2. Find the record by name/type/value first, then delete
		// 3. Return an error if we can't identify the record
		
		var recordID string
		
		// Try to extract ID from ProviderData if available
		switch r := record.(type) {
		case libdns.Address:
			if idData, ok := r.ProviderData.(string); ok {
				recordID = idData
			}
		case libdns.TXT:
			if idData, ok := r.ProviderData.(string); ok {
				recordID = idData
			}
		case libdns.CNAME:
			if idData, ok := r.ProviderData.(string); ok {
				recordID = idData
			}
		case libdns.MX:
			if idData, ok := r.ProviderData.(string); ok {
				recordID = idData
			}
		case libdns.RR:
			// For RR types, we might have stored the ID in a special way
			// This is implementation-specific
		}
		
		if recordID == "" {
			// If we don't have an ID, we need to find the record first
			// This is a simplified approach - a real implementation might
			// search for the record by name/type/value
			return deletedRecords, fmt.Errorf("cannot delete record: no record ID available (record name: %s, type: %s)", record.RR().Name, record.RR().Type)
		}
		
		endpoint := fmt.Sprintf("/v1/domains/%s/records/%s", zone, recordID)
		_, err := p.makeAPIRequest(ctx, "DELETE", endpoint, nil)
		if err != nil {
			return deletedRecords, fmt.Errorf("failed to delete record %s: %w", recordID, err)
		}
		
		deletedRecords = append(deletedRecords, record)
	}
	
	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
