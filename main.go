package main

import (
	"log"
	"os"

	"flag"
	"net"
	"time"
)

var entries map[string]*ServiceEntry

func main() {
	var ifaceName = flag.String("i", "", "interface name")
	var logFile = flag.String("o", "", "log file")
	flag.Parse()

	if len(*logFile) != 0 {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("can't open %s", *logFile)
		}
		defer f.Close()
		log.SetOutput(f)
	}

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

	// send every 300ms as Fing does
	ticker := time.NewTicker(time.Millisecond * 500)
	go func() {
		for {
			select {
			case <-ticker.C:
				err = resolver.Browse("_services._dns-sd._udp", "local.", chResult)
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
				for _, s := range services {
					err = resolver.Browse(s, "local.", chResult)
					if err != nil {
						log.Println("Failed to browse:", err.Error())
					}
					time.Sleep(time.Millisecond * 500)
				}

			}
		}
	}()

	timer := time.NewTimer(time.Second * 60)
	/* cache coherency
	As a general rule, the recommended TTL value for Multicast DNS
	resource records with a host name as the resource record’s name
	(e.g., A, AAAA, HINFO) or a host name contained within the resource
	record’s rdata (e.g., SRV, reverse mapping PTR record) SHOULD be 120
	seconds.
	The recommended TTL value for other Multicast DNS resource records is
	75 minutes(TTL=4500). */
	hostnames := make(map[string]string)
	entries = make(map[string]*ServiceEntry)
	for {
		select {
		case <-timer.C:
			log.Printf("60s passed")
		case r := <-chResult:
			if entry, ok := entries[r.Instance]; !ok {
				entries[r.Instance] = r
				log.Printf("entry: %+v", r)
			} else {
				if entry.HostName != "" {
					// alway trust newer address
					// TODO mutex
					if addr, ok := resolver.c.ipv4AddrCache[entry.HostName]; ok {
						entry.AddrIPv4 = addr
					}
					if addr, ok := resolver.c.ipv6AddrCache[entry.HostName]; ok {
						entry.AddrIPv6 = addr
					}

					// entry is a copy
					entries[r.Instance] = entry
				}
			}

			for _, v := range entries {
				if v.AddrIPv4 != nil && v.HostName != "" {
					if _, ok := hostnames[v.AddrIPv4.String()]; !ok {
						txt, ok := resolver.c.deviceInfo[v.HostName]
						if ok {
							model := queryiDeviceType(txt)
							if model != "" {
								log.Printf("%s:%s at %s", v.HostName, model, v.AddrIPv4.String())
							} else {
								log.Printf("%s:%v at %s", v.HostName, txt, v.AddrIPv4.String())
							}
						} else {
							log.Printf("%s at %s", v.HostName, v.AddrIPv4.String())
						}

						hostnames[v.AddrIPv4.String()] = v.HostName
					}
				}
			}
		}
	}
}
