package rules

import (
	"lazascope/internal/i18n"
	"sort"
	"strconv"
	"strings"

	"lazascope/internal/model"
)

// MITRE ATT&CK is the public catalogue of the methods attackers use, kept
// by the MITRE Corporation. Each method, called a technique, has a number
// such as T1547.001. Security teams the world over file what they find
// under these numbers, so a finding that carries one can be handed to any
// of them without translation.
//
// A rule carries a technique only where what it flags is a trace that the
// technique leaves. A weakness, such as a disk that is not encrypted, is no
// technique, and carries none.

// AttackVersion is the version of ATT&CK that every number below was
// checked against, on attack.mitre.org, on 24 November 2026. ATT&CK moves:
// version 19 gave the techniques for switching defences off numbers of
// their own (T1685 and after), where older lists still say T1562.
const AttackVersion = "20.1"

// Technique is one technique of ATT&CK.
type Technique struct{ ID, Name string }

func (t Technique) String() string { return t.ID + " " + t.Name }

// The techniques the rules name, with ATT&CK's own name for each.
var techniques = map[string]string{
	"T1021.001": "Remote Desktop Protocol",
	"T1027.010": i18n.T("Command Obfuscation"),
	"T1036.001": "Invalid Code Signature",
	"T1036.005": "Match Legitimate Resource Name or Location",
	"T1053.005": "Scheduled Task",
	"T1059":     i18n.T("Command and Scripting Interpreter"),
	"T1078.001": "Default Accounts",
	"T1115":     "Clipboard Data",
	"T1123":     "Audio Capture",
	"T1125":     "Video Capture",
	"T1176.001": i18n.T("Browser Extensions"),
	"T1204.002": "Malicious File",
	"T1219":     "Remote Access Tools",
	"T1496.001": "Compute Hijacking",
	"T1543.003": "Windows Service",
	"T1546.008": i18n.T("Accessibility Features"),
	"T1546.010": "AppInit DLLs",
	"T1546.012": "Image File Execution Options Injection",
	"T1547":     i18n.T("Boot or Logon Autostart Execution"),
	"T1547.001": "Registry Run Keys / Startup Folder",
	"T1547.004": "Winlogon Helper DLL",
	"T1548.002": i18n.T("Bypass User Account Control"),
	"T1552.002": i18n.T("Credentials in Registry"),
	"T1554":     i18n.T("Compromise Host Software Binary"),
	"T1557":     "Adversary-in-the-Middle",
	"T1685":     i18n.T("Disable or Modify Tools"),
	"T1685.005": i18n.T("Clear Windows Event Logs"),
	"T1686.003": "Windows Host Firewall",
}

// The techniques each rule's findings are a trace of. A rule that is not
// here flags a weakness or a fact, and no technique.
var attackOf = map[string][]string{
	"antivirus-off":              {"T1685"},
	"defender-tamper-off":        {"T1685"},
	"defender-exclusions":        {"T1685"},
	"defender-exclusions-logged": {"T1685"},
	"defender-switched-off":      {"T1685"},
	"firewall-off":               {"T1686.003"},
	"uac-off":                    {"T1548.002"},
	"hosts-entries":              {"T1557"},
	"dns-set-by-hand":            {"T1557"},
	"proxy-set":                  {"T1557"},
	"startup-altered":            {"T1554", "T1036.001"},
	"startup-system-name":        {"T1036.005"},
	"startup-scrambled-command":  {"T1027.010", "T1059"},
	"startup-antivirus-objects":  {"T1059"},
	"startup-logon-setting":      {"T1547.004"},
	"startup-debugger":           {"T1546.012"},
	"startup-loaded-library":     {"T1546.010"},
	"startup-script":             {"T1059"},
	"extension-not-from-store":   {"T1176.001"},
	"extension-forced":           {"T1176.001"},
	"running-altered":            {"T1554", "T1036.001"},
	"running-system-name":        {"T1036.005"},
	"running-temp-folder":        {"T1204.002"},
	"running-antivirus-objects":  {"T1059"},
	"running-scrambled-command":  {"T1027.010", "T1059"},
	"remote-desktop-on":          {"T1021.001"},
	"remote-tool":                {"T1219"},
	"guest-on":                   {"T1078.001"},
	"auto-sign-in":               {"T1552.002"},
	"builtin-administrator-on":   {"T1078.001"},
	"log-cleared":                {"T1685.005"},
	"extension-fake-wallet":      {"T1176.001"},
	"hosts-crypto-redirect":      {"T1557"},
	"running-miner":              {"T1496.001"},
	"clipboard-address-swapped":  {"T1115"},
}

// The rules about a start-up entry whose findings also carry the technique
// of the way the entry starts: a line in the Run list, a scheduled task, a
// service. Whatever else is odd about such an entry, that is how it stays.
var staying = map[string]bool{
	"startup-altered": true, "startup-system-name": true, "startup-scrambled-command": true, "startup-antivirus-objects": true,
	"startup-temp-folder": true, "startup-user-folder": true, "startup-unsigned": true, "startup-script": true,
}

// kindTechnique returns the technique of a way of starting by itself.
func kindTechnique(kind model.StartupKind) string {
	switch kind {
	case model.RunKey, model.RunOnceKey, model.StartupFolder:
		return "T1547.001"
	case model.ScheduledTask:
		return "T1053.005"
	case model.Service, model.Driver:
		return "T1543.003"
	case model.LogonSetting:
		return "T1547.004"
	case model.DebuggerSetting:
		return "T1546.012"
	case model.LoadedLibrary:
		return "T1546.010"
	case model.BrowserExtension:
		return "T1176.001"
	case model.StoreApp:
		return "T1547"
	}
	return ""
}

// with adds technique numbers to a list, each once, keeping the order.
func with(list []string, more ...string) []string {
	for _, id := range more {
		have := false
		for _, in := range list {
			have = have || in == id
		}
		if id != "" && !have {
			list = append(list, id)
		}
	}
	return list
}

// tag gives a finding its techniques: the ones the rule that made it names,
// any the rule added for this finding alone, and, for a start-up entry, the
// technique of the way it starts.
func tag(s *model.Snapshot, rule *Rule, f *Finding) {
	f.Attack = with(with(nil, attackOf[rule.ID]...), f.Attack...)
	if staying[rule.ID] && strings.HasPrefix(f.Ref, "startup:") {
		if index, err := strconv.Atoi(strings.TrimPrefix(f.Ref, "startup:")); err == nil && index >= 0 && index < len(s.Startup) {
			f.Attack = with(f.Attack, kindTechnique(s.Startup[index].Kind))
		}
	}
}

// Techniques returns the techniques with the given numbers, in that order.
// A number that is not in the list above is left out.
func Techniques(ids []string) []Technique {
	var out []Technique
	for _, id := range ids {
		if name, known := techniques[id]; known {
			out = append(out, Technique{id, name})
		}
	}
	return out
}

// Attack writes a finding's techniques on one line, or "" when it has none.
func Attack(ids []string) string {
	var parts []string
	for _, technique := range Techniques(ids) {
		parts = append(parts, technique.String())
	}
	return strings.Join(parts, "; ")
}

// Named returns every technique that a rule's findings can carry, sorted
// by number.
func Named(rule string) []string {
	ids := with(nil, attackOf[rule]...)
	if staying[rule] {
		for kind := model.RunKey; kind <= model.BrowserExtension; kind++ {
			ids = with(ids, kindTechnique(kind))
		}
	}
	if rule == "startup-debugger" {
		ids = with(ids, "T1546.008")
	}
	if rule == "device-used-unsigned" {
		ids = with(ids, "T1123", "T1125") // the microphone or the camera, by finding
	}
	sort.Strings(ids)
	return ids
}

// AttackNote says in a line which techniques a rule's findings carry, for
// the table of rules. It is "" for a rule that names none.
func AttackNote(rule string) string {
	var parts []string
	for _, technique := range Techniques(attackOf[rule]) {
		parts = append(parts, technique.String())
	}
	if rule == "startup-debugger" {
		parts = append(parts, "T1546.008 Accessibility Features, for a program that can be opened from the sign-in screen")
	}
	if staying[rule] {
		parts = append(parts, i18n.T("and the technique of the way the entry starts"))
	}
	if rule == "device-used-unsigned" {
		parts = append(parts, "T1125 Video Capture for the camera; T1123 Audio Capture for the microphone")
	}
	return strings.Join(parts, "; ")
}

// Covered returns every technique that some rule can name, each with the
// rules that name it, sorted by number.
func Covered() map[string][]string {
	covered := map[string][]string{}
	for _, rule := range All() {
		for _, id := range Named(rule.ID) {
			covered[id] = append(covered[id], rule.ID)
		}
	}
	for id := range covered {
		sort.Strings(covered[id])
	}
	return covered
}

// KindTechnique returns the technique of a way of starting by itself, with
// its name, for the documents.
func KindTechnique(kind model.StartupKind) Technique {
	id := kindTechnique(kind)
	return Technique{id, techniques[id]}
}
