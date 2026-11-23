package netconn

import "testing"

func TestResolver(t *testing.T) {
	for address, want := range map[string]string{
		"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700:0:0:0:0:1001": "Cloudflare",
		"8.8.8.8": "Google", "8.8.4.4": "Google", "2001:4860:4860::8844": "Google",
		"9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "2620:fe::fe": "Quad9",
		"208.67.222.222": "OpenDNS", "94.140.14.14": "AdGuard",
		" 1.1.1.1 ": "Cloudflare", "::ffff:8.8.8.8": "Google", "fe80::1%12": "",
		"192.168.1.1": "", "203.0.113.53": "", "1.1.1.4": "", "not an address": "", "": "",
	} {
		if got := Resolver(address); got != want {
			t.Errorf("Resolver(%q) = %q, want %q", address, got, want)
		}
	}
	// Every address in the list is one, and each is listed for one owner.
	if len(resolvers) != 42 {
		t.Errorf("the list holds %d addresses, want 42: one may be written twice", len(resolvers))
	}
}

func TestPlaceholder(t *testing.T) {
	for address, want := range map[string]bool{
		"fec0:0:0:ffff::1": true, "fec0:0:0:ffff::2%1": true, "fec0:0:0:ffff::3": true,
		"fec0:0:0:ffff::4": false, "192.168.1.1": false, "": false, "x": false,
	} {
		if got := Placeholder(address); got != want {
			t.Errorf("Placeholder(%q) = %v", address, got)
		}
	}
}

func TestHostPort(t *testing.T) {
	for _, test := range []struct{ text, host, port string }{
		{"127.0.0.1:8080", "127.0.0.1", "8080"},
		{"proxy.example.net:3128", "proxy.example.net", "3128"},
		{"http://proxy.example.net:3128/", "proxy.example.net", "3128"},
		{"proxy.example.net", "proxy.example.net", ""},
		{"[::1]:9000", "::1", "9000"},
		{"[::1]", "::1", ""},
		{"::1", "::1", ""},
		{" localhost:80 ", "localhost", "80"},
		{"", "", ""},
	} {
		if host, port := HostPort(test.text); host != test.host || port != test.port {
			t.Errorf("HostPort(%q) = %q, %q; want %q, %q", test.text, host, port, test.host, test.port)
		}
	}
}
