//go:build windows

package protect

import (
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/reg"
	"lazascope/internal/sysdll"
)

var (
	iphlpapi          = sysdll.Load("iphlpapi.dll")
	adaptersAddresses = iphlpapi.NewProc("GetAdaptersAddresses")
)

// adapter mirrors the start of the record Windows keeps for one network
// connection (IP_ADAPTER_ADDRESSES on 64-bit Windows). Only what is read
// here is named.
type adapter struct {
	length, index               uint32
	next                        *adapter
	name                        *byte // the connection's own number, such as {4D36E972-...}
	unicast, anycast, multicast unsafe.Pointer
	servers                     *nameServer
	suffix, description, title  *uint16
	physical                    [8]byte
	physicalLength, flags, mtu  uint32
	kind, status                uint32
}

// nameServer mirrors one entry of a connection's list of name servers.
type nameServer struct {
	length, reserved uint32
	next             *nameServer
	address          unsafe.Pointer // a sockaddr
	addressLength    int32
}

// network reads which name servers this PC asks, and whether this
// account's web traffic is sent through a go-between.
func (c *collector) network() {
	c.nameServers()
	c.proxy()
}

func (c *collector) nameServers() {
	const (
		skipOwnAddresses = 0x1 | 0x2 | 0x4 // the PC's own addresses are not wanted
		tooSmall         = 111
		up               = 1
		loopback         = 24
	)
	size := uint32(32 << 10)
	var buffer []byte
	for range 4 {
		buffer = make([]byte, size)
		r, _, _ := adaptersAddresses.Call(0, skipOwnAddresses, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
		if r == 0 {
			break
		}
		if r != tooSmall {
			c.gap(model.Protection, "The list of network connections could not be read, so the name servers this PC asks are not known.")
			return
		}
		buffer = nil
	}
	if buffer == nil {
		return
	}
	c.guard.NameServersRead = true
	seen := map[string]bool{}
	for a, n := (*adapter)(unsafe.Pointer(&buffer[0])), 0; a != nil && n < 256; a, n = a.next, n+1 {
		if a.status != up || a.kind == loopback {
			continue
		}
		id := ansi(a.name)
		byHand := typedIn(id)
		for server, m := a.servers, 0; server != nil && m < 32; server, m = server.next, m+1 {
			address := socketAddress(server.address, server.addressLength)
			if address == "" || netconn.Placeholder(address) || seen[address] {
				continue
			}
			seen[address] = true
			c.guard.NameServers = append(c.guard.NameServers, model.NameServer{Address: address, Connection: wide(a.title), ByHand: byHand[address]})
		}
	}
	runtime.KeepAlive(buffer)
}

// typedIn returns the name servers that were typed in on this PC for a
// network connection, as opposed to handed out by the network. Windows
// keeps the two apart in the registry.
func typedIn(connection string) map[string]bool {
	found := map[string]bool{}
	if connection == "" {
		return found
	}
	for _, family := range []string{"Tcpip", "Tcpip6"} {
		servers, _ := reg.Text(reg.Machine, `SYSTEM\CurrentControlSet\Services\`+family+`\Parameters\Interfaces\`+connection, reg.Native, "NameServer")
		for _, server := range strings.FieldsFunc(servers, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if ip, err := netip.ParseAddr(server); err == nil {
				found[ip.Unmap().WithZone("").String()] = true
			}
		}
	}
	return found
}

// socketAddress reads the address out of a sockaddr.
func socketAddress(p unsafe.Pointer, length int32) string {
	const v4, v6 = 2, 23
	if p == nil || length < 16 {
		return ""
	}
	raw := unsafe.Slice((*byte)(p), length)
	switch family := uint16(raw[0]) | uint16(raw[1])<<8; {
	case family == v4:
		return netip.AddrFrom4([4]byte(raw[4:8])).String()
	case family == v6 && length >= 24:
		return netip.AddrFrom16([16]byte(raw[8:24])).Unmap().String()
	}
	return ""
}

// ansi reads a short piece of plain text that Windows hands over as a pointer.
func ansi(p *byte) string {
	if p == nil {
		return ""
	}
	var text []byte
	for i := 0; i < 128; i++ {
		b := *(*byte)(unsafe.Add(unsafe.Pointer(p), i))
		if b == 0 {
			break
		}
		text = append(text, b)
	}
	return string(text)
}

// proxy reads the go-between set for this account's web traffic. Windows
// keeps it per account unless a policy says it is one for the whole PC.
func (c *collector) proxy() {
	const settings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	root, whole := syscall.Handle(reg.User), false
	if perUser, ok := reg.Number(reg.Machine, `SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`, reg.Native, "ProxySettingsPerUser"); ok && perUser == 0 {
		root, whole = reg.Machine, true
	}
	key, err := reg.Open(root, settings, reg.Native)
	if err != nil {
		return
	}
	defer key.Close()
	on, _ := key.Number("ProxyEnable")
	server, _ := key.Text("ProxyServer")
	script, _ := key.Text("AutoConfigURL")
	c.guard.Proxy = model.Proxy{Read: true, AllUsers: whole, Script: strings.TrimSpace(script)}
	if on == 1 && strings.TrimSpace(server) != "" {
		c.guard.Proxy.Server = strings.TrimSpace(server)
	}
}
