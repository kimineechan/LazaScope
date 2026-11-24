// Package privacy reads the defences Windows and Microsoft Defender have
// and whether each is on, what the PC shows of backups, and which programs
// used the camera and the microphone, from the records Windows keeps for
// its privacy settings. It only reads.
//
// The pure part, here, turns the records' raw forms into plain ones.
package privacy

import (
	"encoding/binary"
	"strings"
	"time"
)

// filetime turns eight bytes holding a Windows time into a time, or the
// zero time for none.
func filetime(data []byte) time.Time {
	if len(data) < 8 {
		return time.Time{}
	}
	value := binary.LittleEndian.Uint64(data)
	const between = 116444736000000000 // 1601 to 1970, in 100-nanosecond steps
	if value <= between {
		return time.Time{}
	}
	return time.Unix(0, int64(value-between)*100).UTC()
}

// programPath turns the name Windows gives a program in its privacy
// records, with # in place of each backslash, back into a path.
func programPath(name string) string { return strings.ReplaceAll(name, "#", `\`) }

// backupNames are words in the names of programs that back files up.
var backupNames = []string{"macrium reflect", "acronis", "veeam agent", "backblaze", "carbonite", "idrive", "arq backup", "duplicati",
	"easeus todo backup", "aomei backupper", "paragon backup", "cobian", "crashplan", "urbackup", "synology active backup"}

// BackupProgram reports whether an installed program's name is that of a
// backup program.
func BackupProgram(name string) bool {
	n := strings.ToLower(name)
	for _, word := range backupNames {
		if strings.Contains(n, word) {
			return true
		}
	}
	return false
}
