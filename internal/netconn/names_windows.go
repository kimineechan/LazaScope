//go:build windows

package netconn

import (
	"net/netip"
	"strings"
	"syscall"
	"unsafe"

	"lazascope/internal/sysdll"
)

// Windows remembers, for a while, each name a program asked it to look up
// and the address that came back. It is what "ipconfig /displaydns" shows.
// Reading that note gives many of the addresses in the connection list a
// name, and sends nothing: no lookup is made.

var (
	dnsapi     = sysdll.Load("dnsapi.dll")
	cacheTable = dnsapi.NewProc("DnsGetCacheDataTable")
	dnsQuery   = dnsapi.NewProc("DnsQuery_W")
	dnsFree    = dnsapi.NewProc("DnsFree")
)

// cacheEntry is one name in Windows' note of recent lookups.
type cacheEntry struct {
	next   *cacheEntry
	name   *uint16
	kind   uint16
	length uint16
	flags  uint32
}

// record is one answer to a lookup, as Windows hands it over.
type record struct {
	next     *record
	name     *uint16
	kind     uint16
	length   uint16
	flags    uint32
	lifetime uint32
	reserved uint32
	data     [16]byte // an address: four bytes, or sixteen
}

const (
	addressV4, addressV6 = 1, 28 // the kinds of answer that hold an address

	// Ask only what Windows already remembers. Nothing goes out on the
	// network: not to a DNS server, and not as a shout on the local network.
	// The last switch is one Windows does not document. Without it Windows
	// holds back what it learnt over another network connection, such as a
	// VPN that has since been switched off, and "ipconfig /displaydns" would
	// show names that this list lacked. The test that reads this PC checks
	// that a question asked this way still sends nothing.
	onlyRemembered = 0x10 | 0x80 | 0x800 | 0x8000 // no query on the wire, no NetBIOS, no multicast, every connection's memory

	freeFlat, freeRecords = 0, 1
	mostNames             = 3000
)

// Names returns, for each address Windows remembers looking up, the names
// that led to it. An address that was reached without a lookup, or whose
// name Windows has forgotten, is not in it. Browsers that do their own
// lookups leave nothing here.
func Names() map[string][]string {
	names := map[string][]string{}
	// These two calls are old and stable, but the first is not one Windows
	// documents. If it is missing or misbehaves, there are simply no names.
	defer func() { recover() }()
	if cacheTable.Find() != nil || dnsQuery.Find() != nil || dnsFree.Find() != nil {
		return names
	}
	var first *cacheEntry
	if ok, _, _ := cacheTable.Call(uintptr(unsafe.Pointer(&first))); ok == 0 || first == nil {
		return names
	}
	seen := 0
	for entry := first; entry != nil; {
		next := entry.next
		if seen < mostNames && entry.name != nil && (entry.kind == addressV4 || entry.kind == addressV6) {
			seen++
			name := strings.TrimSuffix(text(entry.name), ".")
			for _, address := range remembered(entry.name, entry.kind) {
				if name != "" && !contains(names[address], name) && len(names[address]) < 4 {
					names[address] = append(names[address], name)
				}
			}
		}
		if entry.name != nil {
			dnsFree.Call(uintptr(unsafe.Pointer(entry.name)), freeFlat)
		}
		dnsFree.Call(uintptr(unsafe.Pointer(entry)), freeFlat)
		entry = next
	}
	return names
}

// remembered returns the addresses Windows remembers for a name. It asks
// with the switch that forbids a lookup, so a name Windows has forgotten
// gives nothing.
func remembered(name *uint16, kind uint16) []string {
	var results *record
	if failed, _, _ := dnsQuery.Call(uintptr(unsafe.Pointer(name)), uintptr(kind), onlyRemembered, 0, uintptr(unsafe.Pointer(&results)), 0); failed != 0 || results == nil {
		return nil
	}
	defer dnsFree.Call(uintptr(unsafe.Pointer(results)), freeRecords)
	var addresses []string
	for answer, n := results, 0; answer != nil && n < 64; answer, n = answer.next, n+1 {
		switch {
		case answer.kind == addressV4 && answer.length >= 4:
			addresses = append(addresses, netip.AddrFrom4([4]byte(answer.data[:4])).String())
		case answer.kind == addressV6 && answer.length >= 16:
			addresses = append(addresses, netip.AddrFrom16(answer.data).Unmap().String())
		}
	}
	return addresses
}

// text reads a piece of text that Windows hands over as a pointer.
func text(p *uint16) string {
	if p == nil {
		return ""
	}
	// One letter at a time, and never past the end: the text is Windows'
	// own memory, and only as long as it is.
	var units []uint16
	for i := 0; i < 512; i++ {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2))
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return syscall.UTF16ToString(units)
}

func contains(values []string, value string) bool {
	for _, have := range values {
		if strings.EqualFold(have, value) {
			return true
		}
	}
	return false
}
