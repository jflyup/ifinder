package main

import (
	"log"
	"os"
	"os/signal"
	"sync/atomic"

	"flag"
	"net"
	"time"
)

func main() {
	var ifaceName = flag.String("i", "", "interface name")
	var logFile = flag.String("o", "", "output file")
	var serviceType = flag.String("t", "", "service type to browse")
	flag.Parse()

	if len(*logFile) != 0 {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("can't open %s", *logFile)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	log.Printf("start scanning:")
	var resolver *Resolver
	var err error
	if *ifaceName != "" {
		if iface, e := net.InterfaceByName(*ifaceName); e != nil {
			log.Printf("can't open interface %s", *ifaceName)
			os.Exit(1)
		} else {
			resolver, err = NewResolver(iface)
		}
	} else {
		resolver, err = NewResolver(nil)
	}

	if err != nil {
		log.Println("Failed to initialize resolver:", err.Error())
		os.Exit(1)
	}

	chResult := make(chan *ServiceEntry)
	go resolver.Run(chResult)

	c := make(chan os.Signal, 1)
	// for Windows
	statTicker := time.NewTicker(time.Second * 60)
	// The only signal values guaranteed to be present on all systems are
	// Interrupt (send the process an interrupt) and Kill (force the process to exit).
	signal.Notify(c, os.Kill, os.Interrupt)
	go func() {
		for {
			select {
			case <-c:
				// dump statistics
				log.Printf("ipv4 packets: %d", atomic.LoadUint32(&resolver.c.ipv4MsgCount))
				log.Printf("ipv6 packets: %d", atomic.LoadUint32(&resolver.c.ipv6MsgCount))
				os.Exit(0)
			case <-statTicker.C:
				log.Printf("ipv4 packets: %d", atomic.LoadUint32(&resolver.c.ipv4MsgCount))
				log.Printf("ipv6 packets: %d", atomic.LoadUint32(&resolver.c.ipv6MsgCount))
			}
		}
	}()

	// send every 500ms
	ticker := time.NewTicker(time.Millisecond * 500)
	go func() {
		for {
			select {
			case <-ticker.C:
				err = resolver.Browse(metaQuery, "local.", chResult)
				if err != nil {
					log.Println("Failed to browse:", err.Error())
				}
			}
		}
	}()

	// browse services related with Apple devices if any
	t := time.NewTicker(time.Second)
	go func() {
		for {
			select {
			case <-t.C:
				for _, s := range appleServices {
					err = resolver.Browse(s, "local", chResult)
					if err != nil {
						log.Println("Failed to browse:", err.Error())
					}
					time.Sleep(time.Millisecond * 500)
				}

			}
		}
	}()

	/* cache coherency
	As a general rule, the recommended TTL value for Multicast DNS
	resource records with a host name as the resource record’s name
	(e.g., A, AAAA, HINFO) or a host name contained within the resource
	record’s rdata (e.g., SRV, reverse mapping PTR record) SHOULD be 120
	seconds.
	The recommended TTL value for other Multicast DNS resource records is
	75 minutes(TTL=4500). */
	hostnames := make(map[string]string)
	entries := make(map[string]*ServiceEntry)
	for {
		select {
		case r := <-chResult:
			if entry, ok := entries[r.ServiceInstanceName()]; !ok {
				if *serviceType != "" {
					if *serviceType != r.Service {
						break
					}
				}
				// TODO ipv4 may change
				log.Printf("service: %s ipv4: %v ipv6: %v, port: %v, TTL: %d, TXT: %v hostname: %s", r.ServiceInstanceName(), r.AddrIPv4, r.AddrIPv6, r.Port, r.TTL, r.Text, r.HostName)

				entries[r.ServiceInstanceName()] = r
			} else {
				if entry.HostName != "" {
					// alway trust newer address because of expired cache
					if addr := resolver.c.getIPv4AddrCache(entry.HostName); addr != nil {
						// note that entry is a pointer, so we can modify the struct directly
						entry.AddrIPv4 = addr
					}
					if addr := resolver.c.getIPv4AddrCache(entry.HostName); addr != nil {
						entry.AddrIPv6 = addr
					}
				}
			}

			for _, v := range entries {
				if v.AddrIPv4 != nil && v.HostName != "" {
					if _, ok := hostnames[v.AddrIPv4.String()]; !ok {
						log.Printf("%s at %s", v.HostName, v.AddrIPv4.String())
					}

					hostnames[v.AddrIPv4.String()] = v.HostName
				}
			}
		}
	}
}
