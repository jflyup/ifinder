# ifinder
`ifinder` scans for mDNS/DNS-SD published services on the
local network. It issues a mDNS PTR query to the special RR
_services._dns-sd._udp.local for retrieving a list of all currently registered
services on the local link. And for the purpose of finding Apple devices, it also 
issues some PTR queries related to iDevice, such as `_homekit._tcp`, `_apple-mobdev2._tcp`.
If any service instance found, ifinder try to resolve it and find A/AAAA/TXT RRs.

`ifinder` doesn't support to publish services, it just sends queries to the 
multicast addresses(both IPv4 and IPv6), then listens and parses the replies.
It does not rely on a local mDNS responder daemon, it can be used on Windows, Linux, OS X.
