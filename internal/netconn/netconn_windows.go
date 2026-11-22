//go:build windows

package netconn

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"syscall"
	"unsafe"

	"lazascope/internal/model"
	"lazascope/internal/sysdll"
)

var (
	iphlpapi = sysdll.Load("iphlpapi.dll")
	tcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	udpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	ipv4, ipv6     = 2, 23
	tcpWithOwners  = 5 // TCP_TABLE_OWNER_PID_ALL: every connection, with the process it belongs to
	udpWithOwners  = 1 // UDP_TABLE_OWNER_PID
	bufferTooSmall = 122
)

// table asks Windows for one of its connection tables.
func table(proc *syscall.LazyProc, family, class uintptr) []byte {
	size := uint32(64 << 10)
	for range 6 {
		buffer := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if r == 0 {
			return buffer
		}
		if r != bufferTooSmall {
			return nil
		}
		size += 16 << 10 // connections come and go between the two calls
	}
	return nil
}

// port reads a port number. Windows stores it in a 32-bit field with the
// two bytes in network order.
func port(field []byte) int { return int(field[0])<<8 | int(field[1]) }

func v4(field []byte) string { return netip.AddrFrom4([4]byte(field[:4])).String() }
func v6(field []byte) string { return netip.AddrFrom16([16]byte(field[:16])).String() }

// state puts the state of a TCP connection into plain words.
func state(number uint32) string {
	switch number {
	case 2:
		return "Waiting for connections"
	case 3, 4:
		return "Connecting"
	case 5:
		return "Connected"
	case 1, 6, 7, 8, 9, 10, 11, 12:
		return "Closing"
	}
	return ""
}

// Collect lists the connections and the waiting ports. The process names
// and files are filled in afterwards, from the list of running programs.
func Collect() ([]model.Connection, []model.Gap) {
	le := binary.LittleEndian
	var list []model.Connection
	rows := func(buffer []byte, size int, read func(row []byte)) bool {
		if len(buffer) < 4 {
			return false
		}
		count := int(le.Uint32(buffer))
		for i := 0; i < count && 4+(i+1)*size <= len(buffer); i++ {
			read(buffer[4+i*size:])
		}
		return true
	}
	tcp := func(c model.Connection, number uint32) {
		c.Protocol, c.State, c.Listening = "TCP", state(number), number == 2
		if c.Listening {
			c.Remote, c.RemotePort = "", 0
			c.Reach = Listens(c.Local)
		} else {
			c.Reach = Reach(c.Remote)
		}
		list = append(list, c)
	}
	udp := func(c model.Connection) {
		// UDP has no connections, only ports that a program has open to
		// receive on.
		c.Protocol, c.State, c.Listening, c.Reach = "UDP", "Open to receive", true, Listens(c.Local)
		list = append(list, c)
	}
	ok := 0
	// Each row: state, local address, local port, remote address, remote port, process.
	if rows(table(tcpTable, ipv4, tcpWithOwners), 24, func(row []byte) {
		tcp(model.Connection{Local: v4(row[4:]), LocalPort: port(row[8:]), Remote: v4(row[12:]), RemotePort: port(row[16:]), PID: le.Uint32(row[20:])}, le.Uint32(row))
	}) {
		ok++
	}
	// Each row: local address, its scope, local port, remote address, its scope, remote port, state, process.
	if rows(table(tcpTable, ipv6, tcpWithOwners), 56, func(row []byte) {
		tcp(model.Connection{Local: v6(row), LocalPort: port(row[20:]), Remote: v6(row[24:]), RemotePort: port(row[44:]), PID: le.Uint32(row[52:])}, le.Uint32(row[48:]))
	}) {
		ok++
	}
	// Each row: local address, local port, process.
	if rows(table(udpTable, ipv4, udpWithOwners), 12, func(row []byte) {
		udp(model.Connection{Local: v4(row), LocalPort: port(row[4:]), PID: le.Uint32(row[8:])})
	}) {
		ok++
	}
	// Each row: local address, its scope, local port, process.
	if rows(table(udpTable, ipv6, udpWithOwners), 28, func(row []byte) {
		udp(model.Connection{Local: v6(row), LocalPort: port(row[20:]), PID: le.Uint32(row[24:])})
	}) {
		ok++
	}
	var gaps []model.Gap
	if ok < 4 {
		gaps = append(gaps, model.Gap{Area: model.Connections, What: "Part of the table of network connections could not be read."})
	}
	// Connections out to the internet first, then the waiting ports.
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Listening != b.Listening {
			return !a.Listening
		}
		if a.Reach != b.Reach {
			return a.Reach > b.Reach
		}
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		return a.LocalPort < b.LocalPort
	})
	return list, gaps
}
