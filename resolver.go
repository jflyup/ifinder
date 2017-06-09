package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Resolver is the client to run queries
type Resolver struct {
	c    *client
	Exit chan<- bool
}

// NewResolver constructs a Resolver
func NewResolver(iface *net.Interface) (*Resolver, error) {
	c, err := newClient(iface)
	if err != nil {
		return nil, err
	}
	return &Resolver{c, c.closedCh}, nil
}

// Browse for all services of a given type in a given domain
func (r *Resolver) Browse(service, domain string, entries chan<- *ServiceEntry) error {
	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries

	err := r.c.query(params)
	if err != nil {
		r.Exit <- true
		return err
	}

	return nil
}

func (r *Resolver) lookup(instance, service, domain string) error {
	params := defaultParams(service)
	params.Instance = instance
	if domain != "" {
		params.Domain = domain
	}
	params.Rrtype = dns.TypePTR

	err := r.c.query(params)
	if err != nil {
		r.Exit <- true
		return err
	}

	return nil
}

// Run starts to process packets
func (r *Resolver) Run(entries chan<- *ServiceEntry) {
	r.c.mainloop(entries)
}

// defaultParams is used to return a default set of QueryParam's
func defaultParams(service string) *LookupParams {
	return NewLookupParams("", service, "local", make(chan *ServiceEntry))
}

// Client structure incapsulates both IPv4/IPv6 UDP connections
type client struct {
	ipv4conn      *net.UDPConn
	ipv6conn      *net.UDPConn
	scopeIDs      []int // for ipv6 link-local multicast
	closed        bool
	closedCh      chan bool
	closeLock     sync.Mutex
	ipv4Lock      sync.Mutex
	ipv6Lock      sync.Mutex
	ipv4AddrCache map[string]net.IP
	ipv6AddrCache map[string]net.IP
	ipv4MsgCount  uint32
	ipv6MsgCount  uint32
}

// Client structure constructor
func newClient(iface *net.Interface) (*client, error) {
	// The source UDP port in all Multicast DNS responses MUST be 5353 (the
	// well-known port assigned to mDNS). Multicast DNS implementations
	// MUST silently ignore any Multicast DNS responses they receive where
	// the source UDP port is not 5353.

	// TODO we should check if we can use udp port 5353 exclusively(it's not so convenient in go),
	// only if yes, we can receive unicast response(rfc 6762#section-15.1)
	ipv4conn, err := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	if err != nil {
		log.Printf("Failed to bind to udp4 port: %v", err)
	}
	ipv6conn, err := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if err != nil {
		log.Printf("Failed to bind to udp6 port: %v", err)
	}
	if ipv4conn == nil && ipv6conn == nil {
		return nil, fmt.Errorf("failed to bind to any udp port")
	}

	// Join multicast groups to receive announcements from server
	p1 := ipv4.NewPacketConn(ipv4conn)
	p2 := ipv6.NewPacketConn(ipv6conn)
	var scopeIDs []int
	if iface != nil {
		if err := p1.JoinGroup(iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
			return nil, err
		}
		if err := p2.JoinGroup(iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
			return nil, err
		}
		p1.SetMulticastLoopback(false)
		p2.SetMulticastLoopback(false)
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil || addrs == nil ||
				(iface.Flags&net.FlagMulticast) != net.FlagMulticast ||
				(iface.Flags&net.FlagLoopback) == net.FlagLoopback ||
				(iface.Flags&net.FlagUp != net.FlagUp) {
				continue
			}
			// exclude interface which has link-local addr but no ipv4 addr like awdl0
			hasIPv4Addr := false
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					hasIPv4Addr = true
					break
				}
			}
			if !hasIPv4Addr {
				continue
			}

			if err := p1.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
				log.Printf("can't join ipv4 multicast group on interface %s", iface.Name)
			}
			p1.SetMulticastLoopback(false)
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsLinkLocalUnicast() {
					// if the interface has a link-local ipv6 address
					if err := p2.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
						log.Printf("can't join ipv6 linklocal multicast group on interface %s", iface.Name)
					} else {
						p2.SetMulticastLoopback(false)
						// using index as Scope ID
						scopeIDs = append(scopeIDs, iface.Index)
						break
					}
				}
			}
		}
	}
	c := &client{
		ipv4conn:      ipv4conn,
		ipv6conn:      ipv6conn,
		scopeIDs:      scopeIDs,
		closedCh:      make(chan bool),
		ipv4AddrCache: make(map[string]net.IP),
		ipv6AddrCache: make(map[string]net.IP),
	}

	return c, nil
}

type recvedMsg struct {
	// source address of mDNS message
	addr    *net.UDPAddr
	mDNSMsg *dns.Msg
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(result chan<- *ServiceEntry) {
	// start listening for responses
	msgCh := make(chan recvedMsg, 32)
	if c.ipv4conn != nil {
		go c.recv(c.ipv4conn, msgCh)
	}
	if c.ipv6conn != nil {
		go c.recv(c.ipv6conn, msgCh)
	}
	ptrEntries := make(map[string]int)

	// Iterate through channels from listeners goroutines
	var entries map[string]*ServiceEntry
	for !c.closed {
		select {
		case <-c.closedCh:
			c.shutdown()
		case msg := <-msgCh:
			entries = make(map[string]*ServiceEntry)
			sections := append(msg.mDNSMsg.Answer, msg.mDNSMsg.Ns...)
			sections = append(sections, msg.mDNSMsg.Extra...)
			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.PTR:
					// Service Type Enumeration:
					// For this purpose, a special meta-query is defined.  A DNS query for
					// PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
					// set of PTR records, where the rdata of each PTR record is the two-
					// label <Service> name, plus the same domain, e.g.,
					// "_http._tcp.<Domain>".
					if strings.HasPrefix(rr.Hdr.Name, "_services._dns-sd._udp.") {
						m := new(dns.Msg)
						m.SetQuestion(rr.Ptr, dns.TypePTR)
						m.RecursionDesired = false
						if err := c.sendQuery(m); err != nil {
							log.Printf("Failed to query service type %s", rr.Ptr)
						}
					} else if strings.HasSuffix(rr.Ptr, rr.Hdr.Name) {
						// service instance
						if _, ok := ptrEntries[rr.Ptr]; !ok {
							//log.Printf("Ptr: %+v", rr)
							ptrEntries[rr.Ptr] = 1
						}
						m := new(dns.Msg)
						m.SetQuestion(rr.Ptr, dns.TypeANY)
						m.RecursionDesired = false
						if err := c.sendQuery(m); err != nil {
							log.Printf("Failed to query instance %s", rr.Ptr)
						}
					} else if strings.Contains(rr.Hdr.Name, ".in-addr.arpa") {
						// always trust newer address
						s := extractIPv4(rr.Hdr.Name)
						c.setIPv4AddrCache(rr.Ptr, net.ParseIP(trimDot(s)))
					} else if strings.Contains(rr.Hdr.Name, "ip6.arpa") {
						// TODO pull out IPv6
					}

				case *dns.SRV:
					// name compression is processed by github.com/miekg/dns

					// TODO: instance name with unicode is converted to decimal base label
					if instance, st, domain, err := parseServiceName(rr.Hdr.Name); err == nil {
						// use rr.Hdr.Name as key since one host can publish multiple services
						if _, ok := entries[rr.Hdr.Name]; !ok {
							entries[rr.Hdr.Name] = NewServiceEntry(
								instance,
								st,
								domain)
						}
						entries[rr.Hdr.Name].HostName = rr.Target
						entries[rr.Hdr.Name].Port = int(rr.Port)
						entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
					} else {
						log.Printf("illegal service instance: %s", rr.Hdr.Name)
					}
				case *dns.TXT:
					// we have little interest in TXT record except _device_info._tcp
					// pseudo service (it's a TXT record)

					if pos := strings.Index(rr.Hdr.Name, "._device-info._tcp."); pos != -1 {
						// it's tricky to connect this TXT record with a host.
						// Typically, the first DNS name label is the default service instance name
						// and can contain any Unicode characters encoded in UTF-8.
						// iPhone/iPad advertises some services(such as _apple-mobdev2._tcp, _homekit._tcp)
						// using special instance name(for example, _apple-mobdev2._tcp uses mac+ipv6 as it,
						// 90:72:40:ba:0b:e9\@fe80::9272:40ff:feba:be9._apple-mobdev2._tcp.local),
						// then this TXT record chooses another instance name or use hostname as
						// instance name. If so, things get complicated.
						instanceName := rr.Hdr.Name[:pos]
						if _, ok := entries[rr.Hdr.Name]; !ok {
							entries[rr.Hdr.Name] = NewServiceEntry(
								instanceName,
								"_device-info._tcp",
								"local")
							entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
							if ipv4 := msg.addr.IP.To4(); ipv4 != nil {
								entries[rr.Hdr.Name].AddrIPv4 = ipv4
							} else {
								entries[rr.Hdr.Name].AddrIPv6 = msg.addr.IP
							}
						}
						// don't append, just overwrite
						entries[rr.Hdr.Name].Text = rr.Txt
					}
					// type NSEC, not used.
				case *dns.A:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							// always trust newer addr except link-local address(169.254.*.*)
							if !rr.A.IsLinkLocalUnicast() {
								entries[k].AddrIPv4 = rr.A
							}
						}
					}

					// Only an authoritative source for a given record is allowed
					// to issue responses containing that record(rfc 6762#section-6),
					// so the address returned by recvfrom() should be the same with
					//  the advertised A record in a good implementation of mDNS
					if ipv4 := msg.addr.IP.To4(); ipv4 != nil {
						if !rr.A.Equal(msg.addr.IP) {
							log.Printf("DEBUG: A record %v != source addr %v", rr.A, msg.addr)
						}
					}
					c.setIPv4AddrCache(rr.Hdr.Name, rr.A)
				case *dns.AAAA:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv6 = rr.AAAA
						}
					}
					if ipv4 := msg.addr.IP.To4(); ipv4 == nil {
						if !rr.AAAA.Equal(msg.addr.IP) {
							log.Printf("DEBUG: AAAA record %v != source addr %v", rr.AAAA, msg.addr)
						}
					}
					c.setIPv6AddrCache(rr.Hdr.Name, rr.AAAA)
				}
			}
		}

		if len(entries) > 0 {
			// we need a set/multiset here, shamelessly go doesn't provide one
			instanceSet := make(map[string]bool)
			hostnameSet := make(map[string]bool)

			var deviceInfos []*ServiceEntry
			for k, e := range entries {
				if e.TTL == 0 {
					delete(entries, k)
					continue
				}
				// check if _device-info._tcp record is alone

				// devices register a _device-info record when at least one service is advertised,
				// but according to what I see in Wireshark, some iPhone/iPads sometimes advertise
				// only a _device-info._tcp record, so we don't know who advertises it, in this scenario,
				// try to ask a question requesting unicast responses(rfc 6762#section-5.4), then we may
				// get the device ip
				if e.Service == "_device-info._tcp" {
					deviceInfos = append(deviceInfos, e)
				} else {
					instanceSet[e.Instance] = true
					hostnameSet[e.HostName] = true
				}

				result <- e
			}

			for _, device := range deviceInfos {
				if _, ok := instanceSet[device.Instance]; !ok {
					// request unicast response
					m := new(dns.Msg)
					m.SetQuestion(device.ServiceInstanceName(), dns.TypeTXT)
					m.RecursionDesired = false
					if err := c.sendUnicastQuery(m); err != nil {
						log.Printf("Failed to send question %s requesting unicast response", device.ServiceInstanceName())
					}
				}
			}
			// reset entries
			entries = make(map[string]*ServiceEntry)
		}
	}
}

func (c *client) getIPv4AddrCache(host string) net.IP {
	c.ipv4Lock.Lock()
	defer c.ipv4Lock.Unlock()
	if ip, ok := c.ipv4AddrCache[host]; ok {
		return ip
	}

	return nil
}

func (c *client) setIPv4AddrCache(host string, ipv4 net.IP) {
	c.ipv4Lock.Lock()
	defer c.ipv4Lock.Unlock()
	// we don't want ipv4 link-local addr
	if !ipv4.IsLinkLocalUnicast() {
		c.ipv4AddrCache[host] = ipv4
	}
}

func (c *client) getIPv6AddrCache(host string) net.IP {
	c.ipv6Lock.Lock()
	defer c.ipv6Lock.Unlock()
	if ip, ok := c.ipv6AddrCache[host]; ok {
		return ip
	}

	return nil
}

func (c *client) setIPv6AddrCache(host string, ipv6 net.IP) {
	c.ipv6Lock.Lock()
	defer c.ipv6Lock.Unlock()
	c.ipv6AddrCache[host] = ipv6
}

// Shutdown client will close currently open connections & channel
func (c *client) shutdown() {
	c.closeLock.Lock()
	defer c.closeLock.Unlock()

	if c.closed {
		return
	}
	c.closed = true
	close(c.closedCh)

	if c.ipv4conn != nil {
		c.ipv4conn.Close()
	}
	if c.ipv6conn != nil {
		c.ipv6conn.Close()
	}
}

// Data receiving routine reads from connection, unpacks packets into dns.Msg
// structures and sends them to a given msgCh channel
func (c *client) recv(l *net.UDPConn, msgCh chan recvedMsg) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)
	for !c.closed {
		n, raddr, err := l.ReadFrom(buf)
		if err != nil {
			continue
		}
		udpAddr, _ := raddr.(*net.UDPAddr)
		mDNSMsg := new(dns.Msg)
		if err := mDNSMsg.Unpack(buf[:n]); err != nil {
			// TODO handle Windows 10 mDNS bug later
			//log.Printf("Failed to unpack packet: %v, packet: %d:%v", err, n, buf[:n])
			continue
		}

		// statistics of ipv4/ipv6 packets
		if strings.Contains(raddr.String(), "%") {
			atomic.AddUint32(&c.ipv6MsgCount, 1)
		} else {
			atomic.AddUint32(&c.ipv4MsgCount, 1)
		}
		select {
		case msgCh <- recvedMsg{addr: udpAddr, mDNSMsg: mDNSMsg}:
		case <-c.closedCh:
			return
		}
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
func (c *client) query(params *LookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", strings.Trim(params.Service, "."), strings.Trim(params.Domain, "."))
	if params.Instance != "" {
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
	}

	// send the query
	m := new(dns.Msg)
	if serviceInstanceName != "" {
		if params.Rrtype != 0 {
			m.Question = []dns.Question{
				dns.Question{Name: serviceInstanceName, Qtype: params.Rrtype, Qclass: dns.ClassINET},
			}
		} else {
			// query ANY type?
			m.Question = []dns.Question{
				dns.Question{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
				dns.Question{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
			}
		}
		m.RecursionDesired = false
	} else {
		m.SetQuestion(serviceName, dns.TypePTR)
		m.RecursionDesired = false
	}
	if err := c.sendQuery(m); err != nil {
		return err
	}

	return nil
}

// Pack the dns.Msg and write to available connections (multicast)
func (c *client) sendQuery(msg *dns.Msg) error {
	buf, err := msg.Pack()

	if err != nil {
		return err
	}
	// ignores the Query ID field
	buf[0] = 0
	buf[1] = 0
	if c.ipv4conn != nil {
		if _, err := c.ipv4conn.WriteTo(buf, ipv4Addr); err != nil {
			log.Printf("c.ipv4conn.WriteTo error: %v", err)
			return err
		}
	}
	if c.ipv6conn != nil {
		addr := ipv6Addr
		for _, scope := range c.scopeIDs {
			addr.Zone = fmt.Sprintf("%d", scope)
			if _, err := c.ipv6conn.WriteTo(buf, addr); err != nil {
				log.Printf("c.ipv6conn.WriteTo error: %v", err)
				return err
			}
		}
	}
	return nil
}

// rfc 6762#section-5.4(Questions Requesting Unicast Responses)
func (c *client) sendUnicastQuery(msg *dns.Msg) error {
	// set unicast-response bit
	msg.Question[0].Qclass |= 0x8000
	buf, err := msg.Pack()

	if err != nil {
		return err
	}

	// rfc 6762#section-6.7, query ID is only used in Legacy Unicast Responses
	buf[0] = 0
	buf[1] = 0

	// doesn't implement #section-5.5(Direct Unicast Queries to Port 5353)
	if c.ipv4conn != nil {
		if _, err := c.ipv4conn.WriteTo(buf, ipv4Addr); err != nil {
			log.Printf("c.ipv4conn.WriteTo error: %v", err)
		}
	}
	if c.ipv6conn != nil {
		addr := ipv6Addr
		for _, scope := range c.scopeIDs {
			addr.Zone = fmt.Sprintf("%d", scope)
			if _, err := c.ipv6conn.WriteTo(buf, addr); err != nil {
				log.Printf("c.ipv6conn.WriteTo error: %v", err)
			}
		}
	}
	return nil
}
