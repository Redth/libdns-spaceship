package libdnsspaceship

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ResourceRecordBase contains fields common to all Spaceship DNS record payloads
// (this is intentionally minimal; each specific record type augments this with
// fields appropriate for that type).
type ResourceRecordBase struct {
	Type string `json:"type"`
	Name string `json:"name"`
	TTL  int    `json:"ttl,omitempty"`
}

// Per-type record payloads mirror the API models for clarity and make it easier
// to reason about which fields belong to which record kinds.

type spaceshipA struct {
	ResourceRecordBase
	Address string `json:"address,omitempty"` // A / AAAA
}

type spaceshipTXT struct {
	ResourceRecordBase
	Value string `json:"value,omitempty"` // TXT
}

type spaceshipCNAME struct {
	ResourceRecordBase
	Cname string `json:"cname,omitempty"` // CNAME
}

type spaceshipMX struct {
	ResourceRecordBase
	Exchange   string `json:"exchange,omitempty"`   // MX
	Preference int    `json:"preference,omitempty"` // MX
}

type spaceshipSRV struct {
	ResourceRecordBase
	Service  string      `json:"service,omitempty"`  // SRV (e.g. "_sip")
	Protocol string      `json:"protocol,omitempty"` // SRV (e.g. "_tcp")
	Priority int         `json:"priority,omitempty"`
	Weight   int         `json:"weight,omitempty"`
	Port     interface{} `json:"port,omitempty"` // integer for SRV (or string for other types)
	Target   string      `json:"target,omitempty"`
}

type spaceshipNS struct {
	ResourceRecordBase
	Nameserver string `json:"nameserver,omitempty"` // NS
}

type spaceshipPTR struct {
	ResourceRecordBase
	Pointer string `json:"pointer,omitempty"` // PTR
}

type spaceshipCAA struct {
	ResourceRecordBase
	Flag  *int   `json:"flag,omitempty"` // CAA
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value,omitempty"`
}

// For backward compatibility and to keep a single consolidated shape that the
// rest of the code currently expects, we still provide the original
// spaceshipRecord union type here.  The union mirrors the API's flattened
// JSON model and reuses the typed sub-structures above conceptually.  You
// can migrate conversion logic to use individual typed structs incrementally.
//
// NOTE: keeper of the union: keep fields aligned with the API's JSON names.
// The presence of multiple fields allows flexible (de)serialization of the
// mixed object shapes returned by the API endpoints.

type spaceshipRecordUnion struct {
	ResourceRecordBase

	// type-specific fields (kept flattened for convenience)
	Address    string      `json:"address,omitempty"`
	Cname      string      `json:"cname,omitempty"`
	Value      string      `json:"value,omitempty"`
	Exchange   string      `json:"exchange,omitempty"`
	Preference int         `json:"preference,omitempty"`
	Service    string      `json:"service,omitempty"`
	Protocol   string      `json:"protocol,omitempty"`
	Priority   int         `json:"priority,omitempty"`
	Weight     int         `json:"weight,omitempty"`
	Port       interface{} `json:"port,omitempty"`
	// PortInt is an internal convenience, not serialized
	PortInt         int    `json:"-"`
	Target          string `json:"target,omitempty"`
	Nameserver      string `json:"nameserver,omitempty"`
	Pointer         string `json:"pointer,omitempty"`
	Flag            *int   `json:"flag,omitempty"`
	Tag             string `json:"tag,omitempty"`
	AssociationData string `json:"associationData,omitempty"`
	Usage           int    `json:"usage,omitempty"`
	Selector        int    `json:"selector,omitempty"`
	Matching        int    `json:"matching,omitempty"`
	AliasName       string `json:"aliasName,omitempty"`
	// TLSA/HTTPS-specific fields removed
}

// UnmarshalJSON implements custom unmarshalling to handle mixed-type 'port' fields and
// to gracefully decode the API's flattened payloads into the union struct.
func (s *spaceshipRecordUnion) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// helper to unmarshal if present
	unmarshal := func(key string, v interface{}) {
		if b, ok := raw[key]; ok {
			json.Unmarshal(b, v) // ignore errors for flexible parsing
		}
	}
	unmarshal("type", &s.Type)
	unmarshal("name", &s.Name)
	unmarshal("ttl", &s.TTL)
	unmarshal("address", &s.Address)
	unmarshal("cname", &s.Cname)
	unmarshal("value", &s.Value)
	unmarshal("exchange", &s.Exchange)
	unmarshal("preference", &s.Preference)
	unmarshal("service", &s.Service)
	// protocol may be present and should be a string
	if b, ok := raw["protocol"]; ok {
		var p string
		if err := json.Unmarshal(b, &p); err == nil {
			s.Protocol = p
		}
	}
	unmarshal("priority", &s.Priority)
	unmarshal("weight", &s.Weight)
	// handle the port value which can be a number or a string (e.g. "_443")
	if b, ok := raw["port"]; ok {
		// try numeric first
		var n int
		if err := json.Unmarshal(b, &n); err == nil {
			s.PortInt = n
			s.Port = n
		} else {
			var ps string
			if err := json.Unmarshal(b, &ps); err == nil {
				s.Port = ps
				if strings.HasPrefix(ps, "_") {
					if v, err := strconv.Atoi(strings.TrimPrefix(ps, "_")); err == nil {
						s.PortInt = v
					}
				} else {
					if v, err := strconv.Atoi(ps); err == nil {
						s.PortInt = v
					}
				}
			}
		}
	}
	unmarshal("target", &s.Target)
	unmarshal("nameserver", &s.Nameserver)
	unmarshal("pointer", &s.Pointer)
	// flag for CAA may be numeric
	if b, ok := raw["flag"]; ok {
		var f int
		if err := json.Unmarshal(b, &f); err == nil {
			s.Flag = &f
		}
	}
	unmarshal("tag", &s.Tag)
	unmarshal("associationData", &s.AssociationData)
	unmarshal("usage", &s.Usage)
	unmarshal("selector", &s.Selector)
	unmarshal("matching", &s.Matching)
	unmarshal("aliasName", &s.AliasName)
	return nil
}
