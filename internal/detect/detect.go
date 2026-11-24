// Package detect holds LazaScope's detections as code: small, readable
// rules that look at each program as it starts, during a live watch, and
// say when one does something attackers are known to do, such as Word
// starting PowerShell or a command that deletes Windows' backups.
//
// Each detection is written out here in plain Go, with its reason, the
// MITRE ATT&CK technique it stands for and a test that makes it fire, so
// that anyone can read exactly what it matches. It is pure: it never
// touches the PC.
package detect

import (
	"regexp"
	"strings"
	"time"

	"lazascope/internal/cmdline"
	"lazascope/internal/rules"
	"lazascope/internal/winpath"
)

// Event is one program starting.
type Event struct {
	When    time.Time
	PID     uint32
	Parent  uint32
	Name    string // its file's name, such as powershell.exe
	Path    string // its file, when Windows says
	Command string // its command line, when Windows says
	By      string // the name of the program that started it
}

// Detection is one rule for programs starting.
type Detection struct {
	ID       string
	Title    string
	Why      string
	Severity rules.Severity
	Attack   []string // ATT&CK technique numbers
	match    func(e Event, name, command string) bool
}

// Alert is a detection that fired.
type Alert struct {
	Detection
	Event Event
}

// Techniques names the ATT&CK techniques the detections stand for, as
// attack.mitre.org names them (version 20.1, checked on 24 November 2026).
var Techniques = map[string]string{
	"T1003.001": "OS Credential Dumping: LSASS Memory",
	"T1027.010": "Obfuscated Files or Information: Command Obfuscation",
	"T1047":     "Windows Management Instrumentation",
	"T1053.005": "Scheduled Task/Job: Scheduled Task",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.001": "Command and Scripting Interpreter: PowerShell",
	"T1105":     "Ingress Tool Transfer",
	"T1112":     "Modify Registry",
	"T1136.001": "Create Account: Local Account",
	"T1140":     "Deobfuscate/Decode Files or Information",
	"T1197":     "BITS Jobs",
	"T1204.002": "User Execution: Malicious File",
	"T1218.005": "System Binary Proxy Execution: Mshta",
	"T1218.010": "System Binary Proxy Execution: Regsvr32",
	"T1218.011": "System Binary Proxy Execution: Rundll32",
	"T1490":     "Inhibit System Recovery",
	"T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
	"T1685":     "Disable or Modify Tools",
}

var (
	office  = set("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe")
	shells  = set("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe")
	posh    = set("powershell.exe", "pwsh.exe", "powershell_ise.exe")
	web     = regexp.MustCompile(`(?i)\bhttps?://`)
	fetches = regexp.MustCompile(`(?i)\b(invoke-webrequest|iwr|invoke-restmethod|irm|downloadstring|downloadfile|downloaddata|start-bitstransfer|wget|curl)\b`)
)

func set(names ...string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

// All are the detections, in the order they are checked.
var All = []Detection{
	{"office-starts-shell", "An Office program started a command tool",
		"Word, Excel and the other Office programs have no reason to start PowerShell, the command prompt or a script host. A document whose macro does so is the most common way malware gets in through email.",
		rules.High, []string{"T1204.002", "T1059"},
		func(e Event, name, _ string) bool { return office[strings.ToLower(e.By)] && shells[name] }},
	{"powershell-encoded", "PowerShell was handed an encoded command",
		"An encoded command is a long run of letters and digits that hides what PowerShell is told to do. Some management tools use it; so does a great deal of malware.",
		rules.Medium, []string{"T1027.010", "T1059.001"},
		func(e Event, name, _ string) bool { return posh[name] && cmdline.Encoded(e.Command) }},
	{"tool-downloads", "A tool of Windows' own was used to download something",
		"certutil, bitsadmin and PowerShell can fetch files from the internet. Attackers use them because they are signed by Microsoft and seldom blocked.",
		rules.Medium, []string{"T1105"},
		func(e Event, name, command string) bool {
			switch {
			case name == "certutil.exe":
				return web.MatchString(command) && (strings.Contains(command, "urlcache") || strings.Contains(command, "verifyctl"))
			case name == "bitsadmin.exe":
				return strings.Contains(command, "/transfer") || strings.Contains(command, "/addfile")
			case posh[name]:
				return web.MatchString(command) && fetches.MatchString(command)
			}
			return false
		}},
	{"certutil-decode", "certutil was used to decode a file",
		"certutil is a certificate tool. Its -decode switch turns text back into a program, a known way to bring a program past filters as harmless-looking text.",
		rules.Medium, []string{"T1140"},
		func(_ Event, name, command string) bool {
			return name == "certutil.exe" && (strings.Contains(command, "-decode") || strings.Contains(command, "/decode"))
		}},
	{"mshta-remote", "mshta ran a script from the internet or from its command line",
		"mshta runs HTML applications. Pointed at a web address, or handed a script directly, it runs that script with the user's rights, past most controls.",
		rules.High, []string{"T1218.005"},
		func(_ Event, name, command string) bool {
			return name == "mshta.exe" && (web.MatchString(command) || strings.Contains(command, "javascript:") || strings.Contains(command, "vbscript:"))
		}},
	{"regsvr32-scriptlet", "regsvr32 was told to run a script",
		"regsvr32 registers program parts. Given /i: with a web address or scrobj.dll, it fetches and runs a script instead, a trick known as Squiblydoo.",
		rules.High, []string{"T1218.010"},
		func(_ Event, name, command string) bool {
			return name == "regsvr32.exe" && (strings.Contains(command, "scrobj.dll") || (strings.Contains(command, "/i:") && web.MatchString(command)))
		}},
	{"rundll32-script", "rundll32 was told to run a script",
		"rundll32 starts functions inside program libraries. Handed javascript: or mshtml's RunHTMLApplication, it runs a script instead.",
		rules.High, []string{"T1218.011"},
		func(_ Event, name, command string) bool {
			return name == "rundll32.exe" && (strings.Contains(command, "javascript:") || strings.Contains(command, "runhtmlapplication"))
		}},
	{"backups-deleted", "A command deleted Windows' backup copies or recovery",
		"Ransomware deletes the copies Windows keeps of files (shadow copies) and switches off recovery before it locks the files, so that they cannot be got back. Almost nothing else does.",
		rules.High, []string{"T1490"},
		func(_ Event, name, command string) bool {
			switch name {
			case "vssadmin.exe":
				return strings.Contains(command, "delete") && strings.Contains(command, "shadows") || strings.Contains(command, "resize shadowstorage")
			case "wmic.exe":
				return strings.Contains(command, "shadowcopy") && strings.Contains(command, "delete")
			case "wbadmin.exe":
				return strings.Contains(command, "delete") && (strings.Contains(command, "catalog") || strings.Contains(command, "systemstatebackup") || strings.Contains(command, "backup"))
			case "bcdedit.exe":
				return strings.Contains(command, "recoveryenabled") && strings.Contains(command, "no") || strings.Contains(command, "ignoreallfailures")
			}
			return posh[name] && strings.Contains(command, "win32_shadowcopy") && (strings.Contains(command, "delete") || strings.Contains(command, "remove-"))
		}},
	{"account-created", "A command made an account, or made one an administrator",
		"Attackers add an account of their own, or raise one to administrator, so that they can come back.",
		rules.High, []string{"T1136.001"},
		func(_ Event, name, command string) bool {
			if name != "net.exe" && name != "net1.exe" {
				return false
			}
			return strings.Contains(command, "/add") && (strings.Contains(command, " user ") || strings.Contains(command, " localgroup "))
		}},
	{"task-created", "A command set up a scheduled task",
		"A scheduled task starts a program at set times or at sign-in. Installers make them, and so does malware that wants to stay.",
		rules.Low, []string{"T1053.005"},
		func(_ Event, name, command string) bool {
			return name == "schtasks.exe" && strings.Contains(command, "/create")
		}},
	{"run-key-added", "A command added a program to the registry's Run list",
		"A line in the registry's Run list starts a program at every sign-in. Adding one from the command line is a quick way to stay on a PC.",
		rules.Medium, []string{"T1547.001", "T1112"},
		func(_ Event, name, command string) bool {
			return (name == "reg.exe" && strings.Contains(command, " add ") || posh[name] && strings.Contains(command, "new-itemproperty")) &&
				strings.Contains(command, `\currentversion\run`)
		}},
	{"defender-changed", "A command switched off part of Defender, or told it to skip a place",
		"Malware tells the antivirus to skip its folder, or switches parts of it off, before doing anything else.",
		rules.High, []string{"T1685"},
		func(_ Event, name, command string) bool {
			if posh[name] && (strings.Contains(command, "add-mppreference") && strings.Contains(command, "exclusion") ||
				strings.Contains(command, "set-mppreference") && (strings.Contains(command, "-disable") || strings.Contains(command, "exclusion"))) {
				return true
			}
			return name == "sc.exe" && strings.Contains(command, "windefend") && (strings.Contains(command, "stop") || strings.Contains(command, "disabled"))
		}},
	{"lsass-dump", "A command copied the memory of the part of Windows that holds passwords",
		"lsass.exe holds the passwords of signed-in accounts in its memory. Copying that memory out, with ProcDump or a function in comsvcs.dll, is how attackers take them.",
		rules.High, []string{"T1003.001"},
		func(_ Event, name, command string) bool {
			return strings.Contains(command, "lsass") && (strings.HasPrefix(name, "procdump") || strings.Contains(command, "minidump") || strings.Contains(command, "comsvcs"))
		}},
	{"wmic-process", "wmic was used to start a program",
		"wmic process call create starts a program through Windows Management Instrumentation, which hides who started it. Attackers use it to move about and to run things quietly.",
		rules.Medium, []string{"T1047"},
		func(_ Event, name, command string) bool {
			return name == "wmic.exe" && strings.Contains(command, "process") && strings.Contains(command, "call") && strings.Contains(command, "create")
		}},
	{"started-from-downloads", "A program started from a temporary or download folder",
		"Installers and portable tools often run from Downloads. So does malware that was just fetched, before it settles somewhere else.",
		rules.Low, []string{"T1204.002"},
		func(e Event, _, _ string) bool {
			p := strings.ToLower(e.Path)
			return strings.HasSuffix(p, ".exe") && (winpath.Has(p, "downloads") || winpath.Has(p, "temp") || winpath.Has(p, "tmp"))
		}},
}

// Check returns the detections an event sets off.
func Check(e Event) []Alert {
	name := strings.ToLower(e.Name)
	if name == "" {
		name = strings.ToLower(winpath.Base(e.Path))
	}
	command := " " + strings.ToLower(e.Command) + " "
	var alerts []Alert
	for _, d := range All {
		if d.match(e, name, command) {
			alerts = append(alerts, Alert{d, e})
		}
	}
	return alerts
}
