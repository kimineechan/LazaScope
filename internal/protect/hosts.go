// Package protect gathers how a PC is protected and who can get into it:
// antivirus, firewall, updates, disk encryption, the accounts with
// administrator rights, remote access and the hosts file.
package protect

import (
	"strings"

	"lazascope/internal/model"
)

// ParseHosts reads the text of a hosts file. Each working line gives an
// address and the names that are to lead to it. Everything after a # is a
// remark, and so is ignored.
//
// The hosts file is a list Windows consults before it asks the internet
// where a website is. A line in it can send a name to any address, which
// is why it is worth reading.
func ParseHosts(text string) []model.HostsEntry {
	var entries []model.HostsEntry
	text = strings.TrimPrefix(text, string(rune(0xFEFF))) // a mark some editors put at the start of a file
	for _, line := range strings.Split(text, "\n") {
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = line[:cut]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entries = append(entries, model.HostsEntry{Address: fields[0], Names: fields[1:]})
	}
	return entries
}
