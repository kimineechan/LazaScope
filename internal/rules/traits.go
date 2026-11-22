package rules

import (
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/winpath"
)

// This file holds the small questions the rules ask about a file's place
// and name. They are plain functions, so that they can be used on their
// own: "is this path in a temporary folder?", "does this name imitate a
// part of Windows?".

// userRest returns the part of a path below one account's folder: for
// C:\Users\sam\Downloads\tool.exe it gives Downloads\tool.exe. ok is false
// for a path that is not in anyone's folder.
func userRest(path string, f model.Folders) (rest string, ok bool) {
	if f.Users == "" || !winpath.Under(path, f.Users) {
		return "", false
	}
	below := winpath.Tidy(path)[len(winpath.Tidy(f.Users)):]
	below = strings.TrimLeft(below, `\`)
	if cut := strings.IndexByte(below, '\\'); cut >= 0 {
		return below[cut+1:], true
	}
	return "", true
}

// Temporary reports whether a file is in a temporary or download folder,
// and names the kind of folder. Installed software lives in Program Files.
// These folders are where things land from the internet and where
// installers unpack, so a program that keeps running from one is unusual.
func Temporary(path string, f model.Folders) (kind string, ok bool) {
	if path == "" {
		return "", false
	}
	switch {
	case f.Temp != "" && winpath.Under(path, f.Temp):
		return "a temporary folder", true
	case f.Windows != "" && winpath.Under(path, winpath.Join(f.Windows, "Temp")):
		return "Windows' temporary folder", true
	case f.Downloads != "" && winpath.Under(path, f.Downloads):
		return "the Downloads folder", true
	case winpath.Has(path, "$Recycle.Bin"):
		return "the Recycle Bin", true
	case winpath.Has(path, "INetCache"), winpath.Has(path, "Temporary Internet Files"):
		return "a web browser's cache", true
	}
	// The same folders in another account.
	if rest, ok := userRest(path, f); ok {
		lower := strings.ToLower(rest)
		switch {
		case strings.HasPrefix(lower, `appdata\local\temp\`):
			return "a temporary folder", true
		case strings.HasPrefix(lower, `downloads\`):
			return "a Downloads folder", true
		}
	}
	return "", false
}

// UserFolder reports whether a file is inside an account's own folder
// (C:\Users\name and below), where any program that account runs can put
// files without asking.
func UserFolder(path string, f model.Folders) bool {
	return path != "" && f.Users != "" && winpath.Under(path, f.Users)
}

// The parts of Windows whose names intruders borrow most. Each of them
// lives in the Windows folder and nowhere else.
var systemNames = map[string]bool{}

func init() {
	for _, name := range strings.Fields(`
		svchost lsass csrss smss wininit winlogon services spoolsv explorer taskhostw taskhost dwm conhost
		rundll32 regsvr32 dllhost ctfmon sihost runtimebroker searchindexer searchprotocolhost searchfilterhost
		userinit logonui fontdrvhost audiodg lsm wuauclt msiexec mshta wscript cscript cmd powershell taskmgr
		regedit wmiprvse werfault wermgr consent sppsvc dashost smartscreen bitsadmin certutil schtasks
		backgroundtaskhost applicationframehost systemsettings securityhealthsystray securityhealthservice
		mmc winver dwwin lsaiso taskeng`) {
		systemNames[name] = true
	}
}

// SystemName reports whether a file is named like one of the well-known
// parts of Windows, such as svchost.exe.
func SystemName(path string) bool {
	return winpath.Ext(path) == ".exe" && systemNames[winpath.Stem(path)]
}

// InWindows reports whether a file is where Windows keeps its own
// programs: inside the Windows folder, but not in one of the corners of it
// that ordinary programs can write to.
func InWindows(path string, f model.Folders) bool {
	if f.Windows == "" || !winpath.Under(path, f.Windows) {
		return false
	}
	for _, corner := range []string{`Temp`, `Tasks`, `tracing`, `debug`, `System32\Tasks`, `SysWOW64\Tasks`, `System32\spool\drivers\color`,
		`System32\FxsTmp`, `SysWOW64\FxsTmp`, `System32\com\dmp`, `SysWOW64\com\dmp`, `Registration\CRMLog`, `System32\Microsoft\Crypto\RSA\MachineKeys`} {
		if winpath.Under(path, winpath.Join(f.Windows, corner)) {
			return false
		}
	}
	return true
}

// Disguised reports whether a file carries the name of a part of Windows
// without being where Windows keeps that part. A copy of svchost.exe in a
// Downloads folder is the classic case.
func Disguised(path string, f model.Folders) bool {
	return winpath.Absolute(path) && SystemName(path) && !InWindows(path, f)
}

// The names worth imitating: the ones people have seen in Task Manager and
// will pass over.
var imitated = strings.Fields("svchost lsass csrss winlogon explorer spoolsv taskhostw rundll32 conhost dllhost wininit runtimebroker searchindexer")

// plain undoes the swaps that make one name look like another on screen:
// a zero for an o, a one or a capital i for an l, and the like.
func plain(name string) string {
	return strings.NewReplacer("0", "o", "1", "l", "i", "l", "3", "e", "5", "s", "vv", "w", "rn", "m").Replace(strings.ToLower(name))
}

// Lookalike reports whether a file's name imitates a part of Windows
// without being the same: svch0st.exe, scvhost.exe, lsasss.exe. It returns
// the name that is imitated.
func Lookalike(path string) (of string, ok bool) {
	// Only programs: among libraries, honest near-misses are common
	// (wininet.dll is one letter from wininit).
	if ext := winpath.Ext(path); ext != ".exe" && ext != ".scr" && ext != ".com" {
		return "", false
	}
	stem := winpath.Stem(path)
	if systemNames[stem] {
		return "", false
	}
	for _, real := range imitated {
		if plain(stem) == plain(real) {
			return real + ".exe", true
		}
		// One letter added, dropped, changed or swapped with its neighbour.
		// Short names are left out: too many honest names are one letter
		// away from "lsass".
		if len(real) >= 6 && nearly(stem, real) {
			return real + ".exe", true
		}
	}
	return "", false
}

// nearly reports whether two different words are one small slip apart.
func nearly(a, b string) bool {
	if a == b {
		return false
	}
	if len(a) < len(b) {
		a, b = b, a
	}
	switch len(a) - len(b) {
	case 0:
		// One letter changed, or two neighbours swapped.
		first := -1
		for i := range a {
			if a[i] != b[i] {
				if first >= 0 {
					return i == first+1 && a[i] == b[first] && a[first] == b[i] && a[i+1:] == b[i+1:]
				}
				first = i
			}
		}
		return true // exactly one letter differs
	case 1:
		// One letter added.
		for i := range b {
			if a[i] != b[i] {
				return a[i+1:] == b[i:]
			}
		}
		return true
	}
	return false
}

// The programs Windows comes with that run whatever script or commands
// they are handed.
var scriptHosts = map[string]bool{"powershell": true, "pwsh": true, "powershell_ise": true, "cmd": true, "wscript": true, "cscript": true, "mshta": true}

// Windows programs that are often borrowed to fetch or run something else.
var helperTools = map[string]bool{"rundll32": true, "regsvr32": true, "certutil": true, "bitsadmin": true, "msiexec": true, "conhost": true, "forfiles": true, "wmic": true, "curl": true}

// ScriptHost reports whether a program is one of Windows' scripting tools.
func ScriptHost(path string) bool { return scriptHosts[winpath.Stem(path)] }

// The endings of script files: text files of commands that a scripting tool
// carries out. The first row is for the tools Windows comes with, the
// second for tools that are often added.
var scriptEndings = map[string]bool{}

func init() {
	for _, ending := range strings.Fields(`
		.bat .cmd .vbs .vbe .js .jse .wsf .wsh .ps1 .hta
		.py .pyw .mjs .cjs .ahk .au3`) {
		scriptEndings[ending] = true
	}
}

// Script reports whether a file is a script, going by the ending of its
// name: a batch file, a PowerShell or VBScript file, and the like.
func Script(path string) bool { return scriptEndings[winpath.Ext(path)] }

// EncodedScript reports whether a file is a script saved in the scrambled
// form Windows offers for VBScript and JScript (.vbe and .jse), which
// cannot be read in Notepad.
func EncodedScript(path string) bool {
	ending := winpath.Ext(path)
	return ending == ".vbe" || ending == ".jse"
}

// Protected reports whether a file is where only an administrator can put
// or change files: the Windows folder and Program Files.
func Protected(path string, f model.Folders) bool {
	if InWindows(path, f) {
		return true
	}
	for _, folder := range []string{f.ProgramFiles, f.ProgramFilesX86} {
		if folder != "" && winpath.Under(path, folder) {
			return true
		}
	}
	return false
}
