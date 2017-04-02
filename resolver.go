package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Main client data structure to run browse/lookup queries
type Resolver struct {
	c    *client
	Exit chan<- bool
}

// Resolver structure constructor
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

func (r *Resolver) Lookup(instance, service, domain string) error {
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

func (r *Resolver) Run(entries chan<- *ServiceEntry) {
	r.c.mainloop(entries)
}

// defaultParams is used to return a default set of QueryParam's
func defaultParams(service string) *LookupParams {
	return NewLookupParams("", service, "local", make(chan *ServiceEntry))
}

// Client structure incapsulates both IPv4/IPv6 UDP connections
type client struct {
	ipv4conn       *net.UDPConn
	ipv6conn       *net.UDPConn
	scopeIDs       []int // for ipv6 link-local multicast
	closed         bool
	closedCh       chan bool
	closeLock      sync.Mutex
	ipv4Lock       sync.Mutex
	ipv6Lock       sync.Mutex
	ipv4AddrCache  map[string]net.IP
	ipv6AddrCache  map[string]net.IP
	deviceInfoLock sync.Mutex
	deviceInfo     map[string]string
}

// Client structure constructor
func newClient(iface *net.Interface) (*client, error) {
	// The source UDP port in all Multicast DNS responses MUST be 5353 (the
	// well-known port assigned to mDNS). Multicast DNS implementations
	// MUST silently ignore any Multicast DNS responses they receive where
	// the source UDP port is not 5353.
	ipv4conn, err := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	if err != nil {
		log.Printf("[ERR] bonjour: Failed to bind to udp4 port: %v", err)
	}
	ipv6conn, err := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if err != nil {
		log.Printf("[ERR] bonjour: Failed to bind to udp6 port: %v", err)
	}
	if ipv4conn == nil && ipv6conn == nil {
		return nil, fmt.Errorf("[ERR] bonjour: Failed to bind to any udp port!")
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
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsLinkLocalUnicast() {
					// if the interface has a link-local ipv6 address
					if err := p2.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
						log.Printf("can't join ipv6 linklocal multicast group on interface %s", iface.Name)
					} else {
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
		deviceInfo:    make(map[string]string),
	}

	return c, nil
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(result chan<- *ServiceEntry) {
	// start listening for responses
	msgCh := make(chan *dns.Msg, 32)
	if c.ipv4conn != nil {
		go c.recv(c.ipv4conn, msgCh)
	}
	if c.ipv6conn != nil {
		go c.recv(c.ipv6conn, msgCh)
	}

	// Iterate through channels from listeners goroutines
	var entries map[string]*ServiceEntry
	for !c.closed {
		select {
		case <-c.closedCh:
			c.shutdown()
		case msg := <-msgCh:
			entries = make(map[string]*ServiceEntry)
			sections := append(msg.Answer, msg.Ns...)
			sections = append(sections, msg.Extra...)
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
						m := new(dns.Msg)
						m.SetQuestion(rr.Ptr, dns.TypeANY)
						m.RecursionDesired = false
						if err := c.sendQuery(m); err != nil {
							log.Printf("Failed to query instance %s", rr.Ptr)
						}
					} else if strings.Contains(rr.Hdr.Name, ".in-addr.arpa") {
						// always trust newer address
						s := reverseIPv4(strings.Replace(rr.Hdr.Name, ".in-addr.arpa", "", 1))
						c.setIPv4AddrCache(rr.Ptr, net.ParseIP(trimDot(s)))
					} else if strings.Contains(rr.Hdr.Name, "ip6.arpa") {
						// TODO pull out IPv6
					}

				case *dns.SRV:
					// name compression is processed by github.com/miekg/dns
					// parse name, TODO: convert octet-based label to unicode string
					ss := strings.Split(rr.Hdr.Name, ".")
					if len(ss) < 3 {
						continue
					}
					// use rr.Hdr.Name as key since one host can publish multiple services
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = NewServiceEntry(
							ss[0],
							ss[1]+"."+ss[2],
							"local")
					}
					entries[rr.Hdr.Name].HostName = rr.Target
					entries[rr.Hdr.Name].Port = int(rr.Port)
					entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
				case *dns.TXT:
					// we have little interest in TXT record except _device_info
					// note the _device-info._tcp pseudo service, it's a TXT record
					if strings.Contains(rr.Hdr.Name, "_device-info._tcp.") {
						hostName := strings.Replace(rr.Hdr.Name, "_device-info._tcp.", "", 1)
						if len(rr.Txt) > 0 {
							c.setDeviceInfo(c.deviceInfo[hostName], rr.Txt[0])
						}
						ss := strings.Split(rr.Hdr.Name, ".")
						if len(ss) < 3 {
							break
						}
						instanceName := ss[0]
						if _, ok := entries[rr.Hdr.Name]; !ok {
							entries[rr.Hdr.Name] = NewServiceEntry(
								instanceName,
								"_device-info._tcp",
								"local")
						}
						if entries[rr.Hdr.Name].HostName == "" {
							entries[rr.Hdr.Name].HostName = hostName
						}
						entries[rr.Hdr.Name].Text = rr.Txt
						entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
					}
					// TODO type NSEC, not necessary?
				case *dns.A:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							// always use newer addr
							entries[k].AddrIPv4 = rr.A
						}
					}
					c.setIPv4AddrCache(rr.Hdr.Name, rr.A)
				case *dns.AAAA:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv6 = rr.AAAA
						}
					}
					c.setIPv6AddrCache(rr.Hdr.Name, rr.AAAA)
				}
			}
		}

		if len(entries) > 0 {
			for k, e := range entries {
				if e.TTL == 0 {
					delete(entries, k)
					continue
				}
				//if e.AddrIPv4 == nil {
				//	if c.getIPv4AddrCache(k)
				//		e.AddrIPv4 = v
				//	}
				//}
				//if e.AddrIPv6 == nil {
				//	if v, ok := c.ipv6AddrCache[k]; ok {
				//		e.AddrIPv6 = v
				//	}
				//}
				result <- e
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
	c.ipv4AddrCache[host] = ipv4
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

func (c *client) setDeviceInfo(host, info string) {
	c.deviceInfoLock.Lock()
	defer c.deviceInfoLock.Unlock()
	c.deviceInfo[host] = info
}

func (c *client) getDeviceInfo(host string) string {
	c.deviceInfoLock.Lock()
	defer c.deviceInfoLock.Unlock()
	if info, ok := c.deviceInfo[host]; ok {
		return info
	}

	return ""
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
func (c *client) recv(l *net.UDPConn, msgCh chan *dns.Msg) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)
	for !c.closed {
		n, _, err := l.ReadFrom(buf)
		if err != nil {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			// TODO handle Windows 10 mDNS bug later
			//log.Printf("[ERR] mdns: Failed to unpack packet: %v, packet: %d:%v", err, n, buf[:n])
			continue
		}
		select {
		case msgCh <- msg:
		case <-c.closedCh:
			return
		}
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
func (c *client) query(params *LookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))
	if params.Instance != "" {
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
	}

	// send the query
	m := new(dns.Msg)
	if serviceInstanceName != "" {
		if params.Rrtype != 0 {
			m.Question = []dns.Question{
				// unicast question?
				dns.Question{serviceInstanceName, params.Rrtype, dns.ClassINET},
			}
		} else {
			// query ANY type?
			m.Question = []dns.Question{
				dns.Question{serviceInstanceName, dns.TypeSRV, dns.ClassINET},
				dns.Question{serviceInstanceName, dns.TypeTXT, dns.ClassINET},
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
