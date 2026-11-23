package rules

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

func server(address string, byHand bool) model.NameServer {
	return model.NameServer{Address: address, Connection: "Wi-Fi", ByHand: byHand}
}

func init() {
	changes = append(changes, []change{
		// Where the PC's questions go.
		{"the router hands out a name server on the internet", guard(func(g *model.Guard) { g.NameServers = []model.NameServer{server("203.0.113.53", false)} }), ""},
		{"a public name server everyone knows, typed in", guard(func(g *model.Guard) {
			g.NameServers = []model.NameServer{server("1.1.1.1", true), server("2606:4700:4700::1111", true)}
		}), ""},
		{"a filter on the home network, typed in", guard(func(g *model.Guard) { g.NameServers = []model.NameServer{server("192.168.1.5", true)} }), ""},
		{"a name server nobody has heard of, typed in", guard(func(g *model.Guard) {
			g.NameServers = []model.NameServer{server("203.0.113.53", true), server("192.168.1.1", false)}
		}), "dns-set-by-hand:medium"},
		{"no network connection is up", guard(func(g *model.Guard) { g.NameServers = nil }), ""},

		// Where the web traffic goes.
		{"web traffic goes through a proxy on the network", guard(func(g *model.Guard) { g.Proxy = model.Proxy{Read: true, Server: "10.0.0.8:3128"} }), "proxy-set:medium"},
		{"a set-up script picks the proxy", guard(func(g *model.Guard) { g.Proxy = model.Proxy{Read: true, Script: "http://wpad.example.net/proxy.pac"} }), "proxy-set:medium"},
		{"a proxy address is stored but switched off", guard(func(g *model.Guard) { g.Proxy = model.Proxy{Read: true} }), ""},
		{"the proxy setting could not be read", guard(func(g *model.Guard) { g.Proxy = model.Proxy{} }), ""},
	}...)
}

func TestNetworkWording(t *testing.T) {
	s := healthy()
	s.Guard.NameServers = []model.NameServer{server("203.0.113.53", true), server("192.168.1.1", false), server("8.8.8.8", true)}
	f := Check(s)[0]
	if f.Subject != "203.0.113.53" || !strings.HasPrefix(f.Reason, "This PC is set by hand to ask 203.0.113.53 for the addresses of websites.") || len(f.Facts) != 1 || f.Facts[0].Value != "203.0.113.53, typed in for the connection Wi-Fi" {
		t.Errorf("the name server finding: %+v", f)
	}

	// A proxy on this PC itself is a program here, and the program is named
	// when it can be seen waiting on that port.
	s = healthy()
	s.Guard.Proxy = model.Proxy{Read: true, Server: "127.0.0.1:9000"}
	f = Check(s)[0]
	for _, want := range []string{
		"This account's web traffic is set to go through 127.0.0.1:9000.",
		"That address is this PC itself, so the go-between is a program running here.",
		"tool.exe is waiting on that port.",
		"Whatever sits there can see the web traffic that passes through it.",
	} {
		if !strings.Contains(f.Reason, want) {
			t.Errorf("the reason lacks %q:\n%s", want, f.Reason)
		}
	}
	if f.Facts[len(f.Facts)-1].Value != `C:\Program Files\Tool\tool.exe` {
		t.Errorf("the facts do not name the program's file: %+v", f.Facts)
	}

	// The same for the forms the setting takes: one go-between for each kind
	// of traffic, a name in place of an address, and one for the whole PC.
	for server, own := range map[string]bool{
		"http=127.0.0.1:9000;https=127.0.0.1:9000": true, "localhost:9000": true, "[::1]:9000": true,
		"proxy.example.net:8080": false, "10.0.0.8:3128": false, "http=proxy.example.net:80": false, "127.0.0.1.example.net:80": false,
	} {
		s = healthy()
		s.Guard.Proxy = model.Proxy{Read: true, Server: server, AllUsers: true}
		f = Check(s)[0]
		if got := strings.Contains(f.Reason, "this PC itself"); got != own {
			t.Errorf("the proxy %q: said to be on this PC = %v", server, got)
		}
		if !strings.Contains(f.Reason, "The setting is one for every account on this PC.") {
			t.Errorf("the proxy %q: not said to be for the whole PC", server)
		}
	}

	// A script and a server together are both said.
	s = healthy()
	s.Guard.Proxy = model.Proxy{Read: true, Server: "10.0.0.8:3128", Script: "http://wpad.example.net/proxy.pac"}
	f = Check(s)[0]
	if !strings.Contains(f.Reason, "go through 10.0.0.8:3128. A script at http://wpad.example.net/proxy.pac decides") || len(f.Facts) != 2 {
		t.Errorf("a proxy with a script: %s %+v", f.Reason, f.Facts)
	}
}
