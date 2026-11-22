package netconn

import (
	"testing"

	"lazascope/internal/model"
)

func TestReach(t *testing.T) {
	for address, want := range map[string]model.Reach{
		"127.0.0.1":       model.ThisPC,
		"127.9.9.9":       model.ThisPC,
		"::1":             model.ThisPC,
		"0.0.0.0":         model.ThisPC,
		"::":              model.ThisPC,
		"192.168.1.20":    model.LocalNetwork,
		"10.0.0.5":        model.LocalNetwork,
		"172.16.4.4":      model.LocalNetwork,
		"172.32.0.1":      model.Internet, // just outside the private range
		"169.254.10.10":   model.LocalNetwork,
		"fe80::1":         model.LocalNetwork,
		"fd12:3456::1":    model.LocalNetwork,
		"224.0.0.251":     model.LocalNetwork,
		"ff02::fb":        model.LocalNetwork,
		"255.255.255.255": model.LocalNetwork,
		"100.64.1.2":      model.LocalNetwork,
		"100.128.0.1":     model.Internet,
		"8.8.8.8":         model.Internet,
		"2606:4700::1111": model.Internet,
		"::ffff:10.0.0.5": model.LocalNetwork, // an IPv4 address written the IPv6 way
		"::ffff:8.8.8.8":  model.Internet,
		"not an address":  model.Internet,
	} {
		if got := Reach(address); got != want {
			t.Errorf("Reach(%s) = %v, want %v", address, got, want)
		}
	}
}

func TestListens(t *testing.T) {
	for address, want := range map[string]model.Reach{
		"127.0.0.1":        model.ThisPC,
		"::1":              model.ThisPC,
		"::ffff:127.0.0.1": model.ThisPC,
		"0.0.0.0":          model.LocalNetwork,
		"::":               model.LocalNetwork,
		"192.168.1.20":     model.LocalNetwork,
		"":                 model.LocalNetwork,
	} {
		if got := Listens(address); got != want {
			t.Errorf("Listens(%s) = %v, want %v", address, got, want)
		}
	}
}

func TestJoin(t *testing.T) {
	if got := Join("192.168.1.20", 443); got != "192.168.1.20:443" {
		t.Errorf("got %s", got)
	}
	if got := Join("2606:4700::1111", 443); got != "[2606:4700::1111]:443" {
		t.Errorf("got %s", got)
	}
}

func TestService(t *testing.T) {
	if Service(443) == "" || Service(3389) != "Remote Desktop" || Service(50123) != "" {
		t.Error("well-known ports are named and others are not")
	}
}
