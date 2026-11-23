package netconn

import (
	"net/netip"
	"strings"
)

// Before a program can reach a website it asks a name server (a DNS
// server) for the site's address. Most PCs ask their router. Some are set
// to ask one of a handful of public services instead, and those are known
// here by name, so that a server nobody has heard of stands out.

// The public name servers people most often set by hand.
var resolvers = map[string]string{}

func init() {
	for owner, addresses := range map[string]string{
		"Cloudflare": `1.1.1.1 1.0.0.1 1.1.1.2 1.0.0.2 1.1.1.3 1.0.0.3
			2606:4700:4700::1111 2606:4700:4700::1001 2606:4700:4700::1112 2606:4700:4700::1002 2606:4700:4700::1113 2606:4700:4700::1003`,
		"Google": `8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844`,
		"Quad9": `9.9.9.9 149.112.112.112 9.9.9.10 149.112.112.10 9.9.9.11 149.112.112.11
			2620:fe::fe 2620:fe::9 2620:fe::10 2620:fe::fe:10 2620:fe::11 2620:fe::fe:11`,
		"OpenDNS": `208.67.222.222 208.67.220.220 208.67.222.123 208.67.220.123 2620:119:35::35 2620:119:53::53`,
		"AdGuard": `94.140.14.14 94.140.15.15 94.140.14.15 94.140.15.16 94.140.14.140 94.140.14.141 2a10:50c0::ad1:ff 2a10:50c0::ad2:ff`,
	} {
		for _, address := range strings.Fields(addresses) {
			resolvers[netip.MustParseAddr(address).String()] = owner
		}
	}
}

// Resolver names the public service a name server belongs to, or returns
// "" for one that is not among the well-known few.
func Resolver(address string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	return resolvers[ip.Unmap().WithZone("").String()]
}

// Placeholder reports whether a name server's address is one of the three
// that Windows fills in for a connection that was given none. Nothing
// answers at them.
func Placeholder(address string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	switch ip.WithZone("").String() {
	case "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3":
		return true
	}
	return false
}

// HostPort splits "host:port" as it is written in a proxy setting, where
// the host may be a name, an address, or an IPv6 address in brackets, and
// the port may be missing. A leading "http://" or the like is dropped.
func HostPort(text string) (host, port string) {
	text = strings.TrimSpace(text)
	if cut := strings.Index(text, "://"); cut >= 0 {
		text = text[cut+3:]
	}
	text = strings.TrimRight(text, "/")
	if strings.HasPrefix(text, "[") {
		if end := strings.IndexByte(text, ']'); end > 0 {
			return text[1:end], strings.TrimPrefix(text[end+1:], ":")
		}
	}
	if cut := strings.LastIndexByte(text, ':'); cut >= 0 && strings.Count(text, ":") == 1 {
		return text[:cut], text[cut+1:]
	}
	return text, ""
}
