package main

import (
	"fmt"
	"net"
)

var (
	// Multicast groups used by mDNS
	mdnsGroupIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	mdnsWildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: 5353,
	}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{
		IP:   net.ParseIP("ff02::"),
		Port: 5353,
	}

	// mDNS endpoint addresses
	ipv4Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv4,
		Port: 5353,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv6,
		Port: 5353,
	}
)

// ServiceRecord contains the basic description of a service, which contains instance name, service type & domain
type ServiceRecord struct {
	Instance string `json:"name"`   // Instance name (e.g. "My web page")
	Service  string `json:"type"`   // Service name (e.g. _http._tcp.)
	Domain   string `json:"domain"` // If blank, assumes "local"

	// private variable populated on the first call to ServiceName()/ServiceInstanceName()
	serviceName         string `json:"-"`
	serviceInstanceName string `json:"-"`
	serviceTypeName     string `json:"-"`
}

// ServiceName returns complete service name (e.g. _foobar._tcp.local.), which is composed
// from a service name (also referred as service type) and a domain.
func (s *ServiceRecord) ServiceName() string {
	if s.serviceName == "" {
		s.serviceName = fmt.Sprintf("%s.%s.", trimDot(s.Service), trimDot(s.Domain))
	}
	return s.serviceName
}

// ServiceInstanceName returns complete service instance name (e.g. MyDemo\ Service._foobar._tcp.local.),
// which is composed from service instance name, service name and a domain.
func (s *ServiceRecord) ServiceInstanceName() string {
	// If no instance name provided we cannot compose service instance name
	if s.Instance == "" {
		return ""
	}
	// If not cached - compose and cache
	if s.serviceInstanceName == "" {
		s.serviceInstanceName = fmt.Sprintf("%s.%s", trimDot(s.Instance), s.ServiceName())
	}
	return s.serviceInstanceName
}

// ServiceTypeName returns complete service type name
func (s *ServiceRecord) ServiceTypeName() string {
	// If not cached - compose and cache
	if s.serviceTypeName == "" {
		domain := "local"
		if len(s.Domain) > 0 {
			domain = trimDot(s.Domain)
		}
		s.serviceTypeName = fmt.Sprintf("_services._dns-sd._udp.%s.", domain)
	}
	return s.serviceTypeName
}

// NewServiceRecord constructs a ServiceRecord structure by given arguments
func NewServiceRecord(instance, service, domain string) *ServiceRecord {
	return &ServiceRecord{instance, service, domain, "", "", ""}
}

// LookupParams contains configurable properties to create a service discovery request
type LookupParams struct {
	ServiceRecord
	Rrtype      uint16
	unicastFlag bool
	Entries     chan<- *ServiceEntry // Entries Channel
}

// NewLookupParams constructs a LookupParams structure by given arguments
func NewLookupParams(instance, service, domain string, entries chan<- *ServiceEntry) *LookupParams {
	return &LookupParams{
		*NewServiceRecord(instance, service, domain),
		0,
		false,
		entries,
	}
}

// ServiceEntry represents a browse/lookup result for client API.
// It is also used to configure service registration (server API), which is
// used to answer multicast queries.
type ServiceEntry struct {
	ServiceRecord
	HostName string   `json:"hostname"` // Host machine DNS name
	Port     int      `json:"port"`     // Service Port
	Text     []string `json:"text"`     // Service info served as a TXT record
	TTL      uint32   `json:"ttl"`      // TTL of the service record
	AddrIPv4 net.IP   `json:"-"`        // Host machine IPv4 address
	AddrIPv6 net.IP   `json:"-"`        // Host machine IPv6 address
}

// NewServiceEntry constructs a ServiceEntry structure by given arguments
func NewServiceEntry(instance, service, domain string) *ServiceEntry {
	return &ServiceEntry{
		*NewServiceRecord(instance, service, domain),
		"",
		0,
		[]string{},
		0,
		nil,
		nil,
	}
}
