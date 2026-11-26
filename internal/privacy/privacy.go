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

	"lazascope/internal/model"
)

// selfEnabling is the build number of Windows 11 22H2. From that release a
// fresh installation switches LSA protection on by itself, the vulnerable
// driver blocklist is on unless someone switches it off, and RunAsPPL set
// to 2 is acted on.
const selfEnabling = 22621

// lsaState works out whether Local Security Authority protection is on.
// setting is RunAsPPL from the registry, and set says whether it is there.
// logged says whether Windows' System log reaches back to when the running
// LSASS started, and protected whether the log holds Wininit's record of
// starting it as a protected process, which is how Microsoft says to check.
// The setting only says what was asked for: a fresh installation of
// Windows 11 22H2 or later switches the protection on without writing it,
// Windows 10 does not act on the value 2, and a protection locked in the
// PC's firmware stays on whatever the registry says.
func lsaState(setting uint32, set, logged, protected bool, build int) (model.Answer, string) {
	recent := build >= selfEnabling
	asked := set && (setting == 1 || setting == 2 && recent)
	why := ""
	if set && setting == 2 && !recent {
		why = "The registry asks for it with the value 2, which only Windows 11 22H2 and later act on. Earlier versions need 1."
	}
	switch {
	case protected:
		return model.Yes, "Windows' own log shows that it has been working since Windows last started."
	case asked && logged:
		return model.No, "It is switched on, but Windows' own log shows that it has not been working since Windows last started. It starts working after a restart."
	case asked:
		return model.Yes, ""
	case logged || set || !recent:
		return model.No, why
	}
	return model.NotKnown, "Windows 11 switches it on by itself on a fresh installation, without a setting in the registry, and Windows' own log does not reach back to when Windows last started, so LazaScope cannot tell."
}

// hvciState works out whether memory integrity is on. setting is Enabled
// from its place in the registry, and set says whether it is there. asked
// says whether Windows' Device Guard report could be read, and running
// whether it lists memory integrity as running. The report is how
// Microsoft says to check: the setting takes effect only after a restart.
func hvciState(setting uint32, set, asked, running bool) (model.Answer, string) {
	switch {
	case running:
		return model.Yes, ""
	case asked && set && setting == 1:
		return model.No, "It is switched on, but Windows reports that it is not running yet. It starts after a restart; if it does not, Windows Security says what stops it."
	case asked:
		return model.No, ""
	case set:
		return model.Say(setting == 1), ""
	}
	return model.NotKnown, ""
}

// blocklistState works out whether the vulnerable driver blocklist is on.
// setting is VulnerableDriverBlocklistEnable from the registry, and set
// says whether it is there. Windows applies the list on every version while
// memory integrity runs, and since Windows 11 22H2 the list is on unless
// someone switches it off.
func blocklistState(setting uint32, set bool, hvci model.Answer, build int) (model.Answer, string) {
	switch {
	case hvci == model.Yes:
		return model.Yes, "Memory integrity is on, and it applies the list."
	case set:
		return model.Say(setting == 1), ""
	case build >= selfEnabling:
		return model.Yes, "Windows 11 has it on unless someone switches it off."
	case hvci == model.No:
		return model.No, "On this version of Windows the list is applied only while memory integrity is on."
	}
	return model.NotKnown, ""
}

// lsassStart returns when the running LSASS, the Local Security Authority,
// started: the earliest lsass.exe in session 0, where Windows' own runs. A
// program that only borrows the name runs elsewhere or starts later.
func lsassStart(table []model.Process) time.Time {
	var start time.Time
	for _, p := range table {
		if p.Session == 0 && strings.EqualFold(p.Name, "lsass.exe") && !p.Started.IsZero() && (start.IsZero() || p.Started.Before(start)) {
			start = p.Started
		}
	}
	return start
}

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
