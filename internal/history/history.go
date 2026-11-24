// Package history reads what Windows remembers of programs having been
// run, and the mark it puts on downloaded files. These are the records
// security analysts call proof of execution: they say that a program ran,
// when, and how often, even after it has closed.
//
//   - UserAssist: what this account opened from the desktop, Explorer and
//     Start, with a count and the last time. Kept in the account's own
//     settings, so no administrator rights are needed. The names are
//     scrambled with ROT13, a shift of each letter by 13 places.
//   - BAM, the Background Activity Moderator: the last time each program
//     ran, by account. Only administrators can read it.
//
// The parsing here is pure, so it is tested with made-up records.
package history

import (
	"encoding/binary"
	"strings"
	"time"

	"lazascope/internal/model"
)

// rot13 undoes the scrambling of UserAssist names: each letter moves 13
// places along the alphabet, and other characters stay as they are.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// filetime turns a Windows time (100-nanosecond steps since 1601) into a
// time, or the zero time for none.
func filetime(value uint64) time.Time {
	if value == 0 || value == ^uint64(0) {
		return time.Time{}
	}
	const between = 116444736000000000 // 1601 to 1970, in 100-nanosecond steps
	if value < between {
		return time.Time{}
	}
	return time.Unix(0, int64(value-between)*100).UTC()
}

// knownFolders are the numbers Windows puts at the start of some UserAssist
// paths in place of a folder, such as {6D809377-...} for Program Files.
var knownFolders = map[string]func(f model.Folders) string{
	"{6D809377-6AF0-444B-8957-A3773F02200E}": func(f model.Folders) string { return f.ProgramFiles },
	"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": func(f model.Folders) string { return f.ProgramFilesX86 },
	"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": func(f model.Folders) string { return f.System },
	"{F38BF404-1D43-42F2-9305-67DE0B28FC23}": func(f model.Folders) string { return f.Windows },
	"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": func(f model.Folders) string { return f.Windows + `\SysWOW64` },
	"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": func(f model.Folders) string { return f.Profile + `\AppData\Local` },
	"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": func(f model.Folders) string { return f.Profile + `\AppData\Roaming` },
	"{374DE290-123F-4565-9164-39C4925E467B}": func(f model.Folders) string { return f.Downloads },
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": func(f model.Folders) string { return f.Profile + `\Desktop` },
	"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": func(f model.Folders) string { return f.Profile + `\Documents` },
}

// expand puts a folder's path in place of its number at the start of a path.
func expand(path string, f model.Folders) string {
	if len(path) < 38 || path[0] != '{' {
		return path
	}
	if folder, ok := knownFolders[strings.ToUpper(path[:38])]; ok {
		if base := folder(f); base != "" {
			return base + path[38:]
		}
	}
	return path
}

// UserAssist turns one UserAssist value into a record: its name, after
// ROT13, and its data, whose layout since Windows 7 is 72 bytes holding the
// count at byte 4, the time in front at byte 12 and the last run at byte 60.
// Counters of Windows' own, which name no program, are left out.
func UserAssist(name string, data []byte, f model.Folders) (model.Run, bool) {
	path := rot13(name)
	if strings.HasPrefix(path, "UEME_") || len(data) < 68 {
		return model.Run{}, false
	}
	r := model.Run{Path: expand(path, f), Source: "UserAssist",
		Count: int(binary.LittleEndian.Uint32(data[4:])),
		Focus: time.Duration(binary.LittleEndian.Uint32(data[12:])) * time.Millisecond,
		Last:  filetime(binary.LittleEndian.Uint64(data[60:]))}
	if r.Last.IsZero() && r.Count == 0 {
		return model.Run{}, false
	}
	return r, true
}

// BAM turns one BAM value into a record: its name is the program's path in
// Windows' inside form, which drive turns into the usual one, and its data
// starts with the last time the program ran.
func BAM(name string, data []byte, drive func(string) string) (model.Run, bool) {
	if len(data) < 8 || !strings.HasPrefix(name, `\`) {
		return model.Run{}, false // Version and SequenceNumber, which are no programs
	}
	path := name
	if d := drive(name); d != "" {
		path = d
	}
	last := filetime(binary.LittleEndian.Uint64(data[:8]))
	if last.IsZero() {
		return model.Run{}, false
	}
	return model.Run{Path: path, Source: "BAM", Last: last}, true
}

// Zone reads the mark Windows puts on a downloaded file, which looks like:
//
//	[ZoneTransfer]
//	ZoneId=3
//	ReferrerUrl=https://example.com/page
//	HostUrl=https://example.com/file.exe
func Zone(text string) (*model.Origin, bool) {
	var o model.Origin
	found := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "zoneid":
			n := 0
			for _, r := range value {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			o.Zone, found = n, true
		case "hosturl":
			o.Host = tidy(value)
		case "referrerurl":
			o.Referrer = tidy(value)
		}
	}
	return &o, found
}

// tidy keeps an address read from a file to one line of reasonable length.
func tidy(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 300 {
		s = string(r[:299]) + "~"
	}
	return s
}

// ZoneName says in words where a zone is.
func ZoneName(zone int) string {
	switch zone {
	case 0:
		return "this PC"
	case 1:
		return "the local network"
	case 2:
		return "a trusted site"
	case 3:
		return "the internet"
	case 4:
		return "a restricted site"
	}
	return "an unknown zone"
}
