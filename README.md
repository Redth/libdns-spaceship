Spaceship for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/Redth/libdns-spaceship)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for Spaceship, allowing you to manage DNS records.

## Configuration

To use this provider, you need a Spaceship API token. Configure the provider as follows:

```go
provider := &libdnsspaceship.Provider{
    APIKey:    "your-spaceship-api-key",
    APISecret: "your-spaceship-api-secret",
}
```

Optionally, you can customize the API base URL (defaults to `https://api.spaceship.com`):

```go
provider := &libdnsspaceship.Provider{
    APIKey:    "your-spaceship-api-key",
    APISecret: "your-spaceship-api-secret",
    BaseURL:   "https://custom-api.spaceship.com",
}
```

## Usage

```go
package main

import (
    "context"
    "time"
    
    "github.com/Redth/libdns-spaceship"
    "github.com/libdns/libdns"
)

func main() {
    provider := &libdnsspaceship.Provider{
        APIKey:    "your-spaceship-api-key",
        APISecret: "your-spaceship-api-secret",
    }
    
    zone := "example.com."
    
    // Get all records
    records, err := provider.GetRecords(context.TODO(), zone)
    if err != nil {
        panic(err)
    }
    
    // Add a new A record
    newRecords := []libdns.Record{
        libdns.Address{
            Name: "test",
            TTL:  300 * time.Second,
            IP:   netip.MustParseAddr("192.0.2.1"),
        },
    }
    
    createdRecords, err := provider.AppendRecords(context.TODO(), zone, newRecords)
    if err != nil {
        panic(err)
    }
}
```

## Supported Record Types

This provider supports the following DNS record types:
- A and AAAA records (`libdns.Address`)
- TXT records (`libdns.TXT`)
- CNAME records (`libdns.CNAME`)  
- MX records (`libdns.MX`)
- Other record types fall back to `libdns.RR`

## API Documentation

For more information about the Spaceship API, see the [official documentation](https://docs.spaceship.dev/).