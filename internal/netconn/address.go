// Package netconn lists the network connections of this PC and the ports
// its programs wait on, each with the program it belongs to. It looks at
// the table Windows keeps. It sends and receives nothing itself.
package netconn

import (
	"net/netip"

	"lazascope/internal/model"
)

// Reach says how far away an address is: on this PC, on the local network,
// or out on the internet.
func Reach(address string) model.Reach {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return model.Internet
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return model.ThisPC
	case ip.IsUnspecified():
		// 0.0.0.0 or :: is no address at all. For a waiting program it
		// means "any network", which Listens deals with.
		return model.ThisPC
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return model.LocalNetwork
	case ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255}:
		return model.LocalNetwork // a shout to everything on the local network
	case ip.Is4() && ip.As4()[0] == 100 && ip.As4()[1]&0xC0 == 64:
		return model.LocalNetwork // the range internet providers and private networks such as Tailscale share
	}
	return model.Internet
}

// Listens says who can reach a program that waits on the given address of
// this PC. Waiting on 127.0.0.1 can only be reached from this PC itself.
// Waiting on 0.0.0.0, which stands for every address the PC has, can be
// reached from other devices, as far as the firewall lets them.
func Listens(address string) model.Reach {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return model.LocalNetwork
	}
	if ip.Unmap().IsLoopback() {
		return model.ThisPC
	}
	return model.LocalNetwork
}

// Service names the usual use of a well-known port, or "".
func Service(port int) string {
	switch port {
	case 20, 21:
		return "file transfer (FTP)"
	case 22:
		return "remote login (SSH)"
	case 23:
		return "remote login (Telnet)"
	case 25, 465, 587:
		return "sending mail"
	case 53:
		return "name lookups (DNS)"
	case 67, 68:
		return "network set-up (DHCP)"
	case 80:
		return "web (HTTP)"
	case 110, 995:
		return "mail (POP3)"
	case 123:
		return "clock setting (NTP)"
	case 135:
		return "Windows remote calls (RPC)"
	case 137, 138, 139:
		return "Windows file sharing (NetBIOS)"
	case 143, 993:
		return "mail (IMAP)"
	case 443:
		return "web (HTTPS)"
	case 445:
		return "Windows file sharing (SMB)"
	case 500, 4500:
		return "VPN (IPsec)"
	case 1900:
		return "device discovery (SSDP)"
	case 3389:
		return "Remote Desktop"
	case 5040:
		return "Windows device platform"
	case 5353:
		return "device discovery (mDNS)"
	case 5355:
		return "name lookups on the local network (LLMNR)"
	case 5357, 3702:
		return "device discovery (WSD)"
	case 5900, 5901:
		return "remote control (VNC)"
	case 5985, 5986:
		return "Windows remote management (WinRM)"
	case 7680:
		return "sharing Windows updates between PCs"
	}
	return ""
}
