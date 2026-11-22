package rules

import (
	"sort"
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
)

// Every test looks at a made-up PC. Nothing here touches the real one.

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	powershell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	encodedRun = `powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`
)

func signed(path, signer string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Signed, Source: sigcheck.Embedded, Signer: signer}}
}

func windows(path string) model.File {
	file := signed(path, "Microsoft Windows")
	file.Signature.Source = sigcheck.Catalogue
	return file
}

func unsigned(path string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}
}

// changed is a signed file that no longer matches its signature.
func changed(path string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Invalid, Signer: "Example Ltd", Code: 0x80096010, Problem: "The file was changed after it was signed."}}
}

// untrusted is a file signed with a certificate Windows does not know.
func untrusted(path string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Invalid, Signer: "Somebody", Code: 0x800B0109, Problem: "It was signed with a certificate that Windows does not trust."}}
}

func script(path string) model.File  { return model.File{Path: path, Exists: true} }
func missing(path string) model.File { return model.File{Path: path} }

// entry is a start-up entry that runs one file directly.
func entry(kind model.StartupKind, name string, file model.File) model.Startup {
	return model.Startup{Kind: kind, Name: name, Where: "a made-up place", Command: file.Path, Program: file, Target: file, Enabled: true}
}

// through is a start-up entry that runs a file by way of a go-between.
func through(kind model.StartupKind, name, command string, host, target model.File) model.Startup {
	return model.Startup{Kind: kind, Name: name, Where: "a made-up place", Command: command, Program: host, Target: target, Enabled: true}
}

// healthy is a PC with nothing wrong with it. It holds a good many things
// that look a little unusual and are fine, so that every test that starts
// from it also proves those stay quiet.
func healthy() *model.Snapshot {
	svchost := windows(`C:\Windows\System32\svchost.exe`)
	notes := signed(`C:\Program Files\Notes\notes.exe`, "Notes Ltd")
	chat := signed(`C:\Users\sam\AppData\Local\Chat\Update.exe`, "Chat Inc.")
	tool := unsigned(`C:\Program Files\Tool\tool.exe`)
	s := &model.Snapshot{Taken: now, Computer: "PC", User: "sam", Windows: "Windows 10 Pro 22H2", Folders: folders}
	s.Startup = []model.Startup{
		entry(model.RunKey, "SecurityHealth", windows(`C:\Windows\System32\SecurityHealthSystray.exe`)),
		entry(model.RunKey, "Chat", chat), // installed for one user, in that user's folder, and signed
		entry(model.StartupFolder, "Notes.lnk", notes),
		entry(model.StoreApp, "Music", signed(`C:\Program Files\WindowsApps\Music_1.0_x64__abc\Music.exe`, "EB51A5DA-0E72-4863-82E4-EA21C1F8DFE3")),
		entry(model.ScheduledTask, `\Chat\Update`, chat), // a signed program keeping itself up to date from a user's folder
		entry(model.ScheduledTask, `\Microsoft\Windows\Defrag\ScheduledDefrag`, windows(`C:\Windows\System32\defrag.exe`)),
		through(model.ScheduledTask, `\Notes\Tidy`, `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Notes\tidy.ps1"`, windows(powershell), script(`C:\Program Files\Notes\tidy.ps1`)),
		through(model.Service, "Audiosrv", `C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p`, svchost, windows(`C:\Windows\System32\audiosrv.dll`)),
		entry(model.Service, "NotesSync", signed(`C:\Program Files\Notes\sync.exe`, "Notes Ltd")),
		entry(model.Driver, "disk", windows(`C:\Windows\System32\drivers\disk.sys`)),
		entry(model.Driver, "gfx", signed(`C:\Windows\System32\DriverStore\FileRepository\gfx.inf_amd64_1\gfx.sys`, "Microsoft Windows Hardware Compatibility Publisher")),
		through(model.LogonSetting, "Shell", "explorer.exe", windows(`C:\Windows\explorer.exe`), windows(`C:\Windows\explorer.exe`)),
		through(model.LogonSetting, "Userinit", `C:\Windows\system32\userinit.exe`, windows(`C:\Windows\system32\userinit.exe`), windows(`C:\Windows\system32\userinit.exe`)),
	}
	s.Processes = []model.Process{
		{PID: 4, Name: "System", User: "SYSTEM"},
		{PID: 800, Parent: 4, Name: "svchost.exe", File: svchost, User: "SYSTEM", Services: []string{"Audiosrv"}, CommandHidden: true},
		{PID: 3000, Name: "explorer.exe", File: windows(`C:\Windows\explorer.exe`), User: "sam", Command: `C:\Windows\explorer.exe`},
		{PID: 3100, Parent: 3000, Name: "notes.exe", File: notes, User: "sam", Command: `"C:\Program Files\Notes\notes.exe"`},
		// Not signed, but properly installed. No rule judges a running program for that alone.
		{PID: 3200, Parent: 3000, Name: "tool.exe", File: tool, User: "sam", Command: `"C:\Program Files\Tool\tool.exe" --serve`},
		{PID: 3300, Parent: 3000, Name: "powershell.exe", File: windows(powershell), User: "sam", Command: `powershell.exe -NoProfile -File C:\Scripts\job.ps1`},
		{PID: 3400, Parent: 3000, Name: "Update.exe", File: chat, User: "sam", Command: `"C:\Users\sam\AppData\Local\Chat\Update.exe" --processStart Chat.exe`},
	}
	s.Connections = []model.Connection{
		{Protocol: "TCP", State: "Connected", Local: "192.168.1.20", LocalPort: 50000, Remote: "93.184.216.34", RemotePort: 443, Reach: model.Internet, PID: 3100, Process: "notes.exe", File: notes},
		{Protocol: "TCP", State: "Connected", Local: "192.168.1.20", LocalPort: 50001, Remote: "93.184.216.34", RemotePort: 443, Reach: model.Internet, PID: 3200, Process: "tool.exe", File: tool},
		{Protocol: "TCP", Listening: true, Local: "0.0.0.0", LocalPort: 445, Reach: model.LocalNetwork, PID: 4, Process: "System"},
		{Protocol: "TCP", Listening: true, Local: "0.0.0.0", LocalPort: 135, Reach: model.LocalNetwork, PID: 800, Process: "svchost.exe", File: svchost},
		// An unsigned program waiting where only this PC can reach it, and on UDP.
		{Protocol: "TCP", Listening: true, Local: "127.0.0.1", LocalPort: 9000, Reach: model.ThisPC, PID: 3200, Process: "tool.exe", File: tool},
		{Protocol: "UDP", Listening: true, Local: "0.0.0.0", LocalPort: 5353, Reach: model.LocalNetwork, PID: 3200, Process: "tool.exe", File: tool},
	}
	s.Guard = model.Guard{
		Antivirus:        []model.SecurityProduct{{Name: "Microsoft Defender Antivirus", On: model.Yes, UpToDate: model.Yes}},
		AntivirusHealth:  model.Yes,
		FirewallHealth:   model.Yes,
		FirewallProducts: []model.SecurityProduct{{Name: "Windows Firewall", On: model.Yes}},
		Firewall:         []model.FirewallProfile{{Name: "Private networks", On: model.Yes}, {Name: "Public networks", On: model.Yes}, {Name: "Work networks", On: model.Yes}},
		RealTime:         model.Yes, Tamper: model.Yes, ExclusionsVisible: true,
		UAC: model.Yes, UACSilent: model.No, Build: "19045.6036", LastUpdate: now.AddDate(0, 0, -9), UpdateKnown: true,
		Volumes: []model.Volume{{Drive: "C:", Encrypted: model.Yes, State: "On"}}, SecureBoot: model.Yes,
		RemoteDesktop: model.No, RemoteNLA: model.Yes,
		Admins:        []model.Account{{Name: "Administrator", BuiltIn: "Administrator", Disabled: model.Yes}, {Name: "sam", Disabled: model.No}},
		AdminsVisible: true, Guest: model.No, AutoSignIn: model.No,
		HostsPath: `C:\Windows\System32\drivers\etc\hosts`, HostsVisible: true,
		Hosts: []model.HostsEntry{{Address: "127.0.0.1", Names: []string{"localhost"}}, {Address: "::1", Names: []string{"localhost"}}},
		// Two programs whose names sound like remote control and are not.
		Programs: []model.Installed{{Name: "Notes"}, {Name: "Chat"}, {Name: "Radmin VPN"}, {Name: "LogMeIn Hamachi"}},
	}
	return s
}

// outcome writes findings as "rule:severity", in a fixed order.
func outcome(findings []Finding) string {
	var parts []string
	for _, f := range findings {
		parts = append(parts, f.Rule+":"+map[Severity]string{High: "high", Medium: "medium", Low: "low"}[f.Severity])
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func TestHealthyPCIsQuiet(t *testing.T) {
	s := healthy()
	if findings := Check(s); len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("a healthy PC was flagged: %s (%s): %s", f.Rule, f.Subject, f.Reason)
		}
	}
	for area, light := range Lights(s, nil) {
		if light != Green {
			t.Errorf("%s shows %v on a healthy PC, want green", model.Area(area), light)
		}
	}
}

// change is one thing done to the healthy PC, and what must be flagged
// because of it. An empty want means: this must stay quiet.
type change struct {
	name string
	do   func(s *model.Snapshot)
	want string
}

func add(entries ...model.Startup) func(*model.Snapshot) {
	return func(s *model.Snapshot) { s.Startup = append(s.Startup, entries...) }
}

func off(e model.Startup) model.Startup {
	e.Enabled = false
	return e
}

func run(p ...model.Process) func(*model.Snapshot) {
	return func(s *model.Snapshot) { s.Processes = append(s.Processes, p...) }
}

var changes = []change{
	// Starts with Windows: signatures.
	{"an unsigned program starts with Windows", add(entry(model.RunKey, "Tool", unsigned(`C:\Program Files\Tool\tool.exe`))), "startup-unsigned:medium"},
	{"the same entry, switched off in Task Manager", add(off(entry(model.RunKey, "Tool", unsigned(`C:\Program Files\Tool\tool.exe`)))), ""},
	{"an unsigned driver", add(entry(model.Driver, "thing", unsigned(`C:\Windows\System32\drivers\thing.sys`))), "startup-unsigned:medium"},
	{"a program signed by a maker Windows does not know", add(entry(model.RunKey, "Odd", untrusted(`C:\Program Files\Odd\odd.exe`))), "startup-unsigned:medium"},
	{"a signed program whose file was changed afterwards", add(entry(model.Service, "Bent", changed(`C:\Program Files\Bent\bent.exe`))), "startup-altered:high"},
	{"a batch file starts with Windows", add(entry(model.RunKey, "Job", script(`C:\Program Files\Job\job.cmd`))), ""},

	// Starts with Windows: place and name.
	{"a signed program starts from the temporary folder", add(entry(model.RunOnceKey, "Setup", signed(`C:\Users\sam\AppData\Local\Temp\is-1\setup.exe`, "Notes Ltd"))), "startup-temp-folder:medium"},
	{"an unsigned program starts from Downloads", add(entry(model.RunKey, "Free", unsigned(`C:\Users\sam\Downloads\free.exe`))), "startup-temp-folder:high startup-unsigned:medium"},
	{"a copy of a Windows program called svchost.exe in Downloads", add(entry(model.RunKey, "Host", windows(`C:\Users\sam\Downloads\svchost.exe`))), "startup-system-name:high startup-temp-folder:medium"},
	{"cmd.exe in the corner of Windows anyone can write to", add(entry(model.ScheduledTask, `\Updater`, windows(`C:\Windows\Temp\cmd.exe`))), "startup-system-name:high startup-temp-folder:medium"},
	{"a name one character from a Windows one", add(entry(model.RunKey, "Host", signed(`C:\Program Files\Thing\svch0st.exe`, "Thing Ltd"))), "startup-system-name:high"},
	{"rundll32 is handed an unsigned library from Downloads", add(through(model.RunKey, "Lib", `rundll32.exe C:\Users\sam\Downloads\thing.dll,Run`, windows(`C:\Windows\System32\rundll32.exe`), unsigned(`C:\Users\sam\Downloads\thing.dll`))),
		"startup-temp-folder:high startup-unsigned:medium"},

	// Starts with Windows: scrambled commands.
	{"PowerShell starts with an encoded command", add(through(model.RunKey, "Upd", encodedRun, windows(powershell), windows(powershell))), "startup-scrambled-command:high"},
	{"a task makes mshta fetch a page from the internet", add(through(model.ScheduledTask, `\Page`, `mshta.exe https://example.com/a.hta`, windows(`C:\Windows\System32\mshta.exe`), windows(`C:\Windows\System32\mshta.exe`))), "startup-scrambled-command:high"},
	{"the same scrambled command, switched off", add(off(through(model.RunKey, "Upd", encodedRun, windows(powershell), windows(powershell)))), ""},
	{"cmd starts an installed program", add(through(model.RunKey, "Start", `cmd.exe /c start "" "C:\Program Files\Notes\notes.exe"`, windows(`C:\Windows\System32\cmd.exe`), signed(`C:\Program Files\Notes\notes.exe`, "Notes Ltd"))), ""},

	// Starts with Windows: settings that are misused.
	{"a debugger set for Task Manager", add(model.Startup{Kind: model.DebuggerSetting, Name: "taskmgr.exe", Subject: "taskmgr.exe", Command: `"C:\Program Files\Tool\view.exe"`, Enabled: true,
		Program: signed(`C:\Program Files\Tool\view.exe`, "Tool Ltd"), Target: signed(`C:\Program Files\Tool\view.exe`, "Tool Ltd")}), "startup-debugger:medium"},
	{"a debugger set for the sticky-keys helper", add(model.Startup{Kind: model.DebuggerSetting, Name: "sethc.exe", Subject: "sethc.exe", Command: `C:\Windows\System32\cmd.exe`, Enabled: true,
		Program: windows(`C:\Windows\System32\cmd.exe`), Target: windows(`C:\Windows\System32\cmd.exe`)}), "startup-debugger:high"},
	{"a signed library set to load into every program", add(entry(model.LoadedLibrary, "hook.dll", signed(`C:\Program Files\Hook\hook.dll`, "Hook Ltd"))), "startup-loaded-library:medium"},
	{"an unsigned library set to load into every program", add(entry(model.LoadedLibrary, "hook.dll", unsigned(`C:\ProgramData\hook.dll`))), "startup-loaded-library:high startup-unsigned:medium"},
	{"a library named there while the setting is switched off", add(off(entry(model.LoadedLibrary, "hook.dll", unsigned(`C:\ProgramData\hook.dll`)))), ""},
	{"a second program added to the sign-in shell", add(through(model.LogonSetting, "Shell", `C:\ProgramData\x\run.exe`, signed(`C:\ProgramData\x\run.exe`, "X Ltd"), signed(`C:\ProgramData\x\run.exe`, "X Ltd"))), "startup-logon-setting:high"},
	{"the desktop is handed something to open at sign-in", add(model.Startup{Kind: model.LogonSetting, Name: "Shell", Command: `explorer.exe C:\x\thing.lnk`, Arguments: `C:\x\thing.lnk`, Enabled: true,
		Program: windows(`C:\Windows\explorer.exe`), Target: windows(`C:\Windows\explorer.exe`)}), "startup-logon-setting:high"},

	// Starts with Windows: user folders.
	{"a task runs an unsigned program from a user's folder", add(entry(model.ScheduledTask, `\Upd`, unsigned(`C:\Users\sam\AppData\Roaming\upd\upd.exe`))), "startup-unsigned:medium startup-user-folder:medium"},
	{"a task runs a script kept in Documents", add(through(model.ScheduledTask, `\Sync`, `"C:\Program Files\nodejs\node.exe" C:\Users\sam\Documents\sync.mjs`, signed(`C:\Program Files\nodejs\node.exe`, "OpenJS Foundation"), script(`C:\Users\sam\Documents\sync.mjs`))),
		"startup-user-folder:medium"},
	{"a service runs a signed program from a user's folder", add(entry(model.Service, "Thing", signed(`C:\Users\sam\AppData\Local\Thing\svc.exe`, "Thing Ltd"))), "startup-user-folder:medium"},
	{"a task in a user's temporary folder is said once, by the rule for those", add(entry(model.ScheduledTask, `\Tmp`, signed(`C:\Users\sam\AppData\Local\Temp\t.exe`, "Thing Ltd"))), "startup-temp-folder:medium"},

	// Starts with Windows: leftovers.
	{"an entry whose file is gone", add(entry(model.RunKey, "Old", missing(`C:\Program Files\Old\old.exe`))), "startup-missing-file:low"},
	{"the same, switched off", add(off(entry(model.RunKey, "Old", missing(`C:\Program Files\Old\old.exe`)))), ""},
	{"one of Windows' own tasks for a feature this PC lacks", add(entry(model.ScheduledTask, `\Microsoft\Windows\Feature\Thing`, missing(`C:\Windows\System32\thing.exe`))), ""},
	{"a Windows driver that is not installed", add(entry(model.Driver, "thing", missing(`C:\Windows\System32\drivers\thing.sys`))), ""},
	{"another maker's driver whose file is gone", add(entry(model.Driver, "thing", missing(`C:\Program Files\Thing\thing.sys`))), "startup-missing-file:low"},
	{"an entry that could not be traced to any file", add(model.Startup{Kind: model.ScheduledTask, Name: `\Odd`, Enabled: true, Untraced: true}), ""},

	// Running now.
	{"an installer is running from the temporary folder", run(model.Process{PID: 9000, Name: "setup.exe", File: signed(`C:\Users\sam\AppData\Local\Temp\is-1\setup.exe`, "Notes Ltd")}), "running-temp-folder:medium"},
	{"an unsigned program is running from Downloads", run(model.Process{PID: 9000, Name: "free.exe", File: unsigned(`C:\Users\sam\Downloads\free.exe`)}), "running-temp-folder:high"},
	{"forty copies of it are running", func(s *model.Snapshot) {
		for i := range 40 {
			s.Processes = append(s.Processes, model.Process{PID: uint32(9000 + i), Name: "free.exe", File: unsigned(`C:\Users\sam\Downloads\free.exe`)})
		}
	}, "running-temp-folder:high"},
	{"a program called svchost.exe is running from a user's folder", run(model.Process{PID: 9000, Name: "svchost.exe", File: windows(`C:\Users\sam\AppData\Roaming\svchost.exe`)}), "running-system-name:high"},
	{"a program with a look-alike name is running", run(model.Process{PID: 9000, Name: "scvhost.exe", File: unsigned(`C:\ProgramData\scvhost.exe`)}), "running-system-name:high"},
	{"a running program's file was changed after signing", run(model.Process{PID: 9000, Name: "bent.exe", File: changed(`C:\Program Files\Bent\bent.exe`)}), "running-altered:high"},
	{"PowerShell is running an encoded command", run(model.Process{PID: 9000, Name: "powershell.exe", File: windows(powershell), Command: encodedRun}), "running-scrambled-command:medium"},
	{"the same, but its command cannot be read", run(model.Process{PID: 9000, Name: "powershell.exe", File: windows(powershell), CommandHidden: true}), ""},
	{"a program Windows will not give the place of", run(model.Process{PID: 9000, Name: "svchost.exe"}), ""},

	// Internet connections.
	{"an unsigned program waits for the network on two ports", func(s *model.Snapshot) {
		tool := unsigned(`C:\Program Files\Tool\tool.exe`)
		for _, c := range []model.Connection{{Local: "0.0.0.0", LocalPort: 8080}, {Local: "::", LocalPort: 8080}, {Local: "192.168.1.20", LocalPort: 3389}} {
			c.Protocol, c.Listening, c.Reach, c.PID, c.Process, c.File = "TCP", true, model.LocalNetwork, 3200, "tool.exe", tool
			s.Connections = append(s.Connections, c)
		}
	}, "listener-unsigned:medium"},
	{"a signed program waits for the network", func(s *model.Snapshot) {
		s.Connections = append(s.Connections, model.Connection{Protocol: "TCP", Listening: true, Local: "0.0.0.0", LocalPort: 27036, Reach: model.LocalNetwork, PID: 3100, Process: "notes.exe", File: signed(`C:\Program Files\Notes\notes.exe`, "Notes Ltd")})
	}, ""},

	// Protection.
	{"Windows Security says antivirus needs attention", func(s *model.Snapshot) { s.Guard.AntivirusHealth = model.No }, "antivirus-off:high"},
	{"the only antivirus is switched off", func(s *model.Snapshot) {
		s.Guard.AntivirusHealth, s.Guard.Antivirus[0].On = model.NotKnown, model.No
	}, "antivirus-off:high"},
	{"Defender's real-time protection is off", func(s *model.Snapshot) { s.Guard.AntivirusHealth, s.Guard.RealTime = model.NotKnown, model.No }, "antivirus-off:high"},
	{"another antivirus is in charge and Defender stands aside", func(s *model.Snapshot) {
		s.Guard.Antivirus = []model.SecurityProduct{{Name: "Microsoft Defender Antivirus", On: model.No}, {Name: "Other Antivirus", On: model.Yes, UpToDate: model.Yes}}
		s.Guard.RealTime, s.Guard.Tamper = model.No, model.No
	}, ""},
	{"antivirus is on but out of date", func(s *model.Snapshot) { s.Guard.Antivirus[0].UpToDate = model.No }, "antivirus-out-of-date:medium"},
	{"Defender's settings are not locked", func(s *model.Snapshot) { s.Guard.Tamper = model.No }, "defender-tamper-off:medium"},
	{"Defender is told to skip a project folder", func(s *model.Snapshot) {
		s.Guard.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `D:\Projects\game`}, {Kind: "Program", Value: "game.exe"}}
	}, "defender-exclusions:medium"},
	{"Defender is told to skip the whole of drive C", func(s *model.Snapshot) {
		s.Guard.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `C:\`}}
	}, "defender-exclusions:high"},
	{"Defender is told to skip the Downloads folder", func(s *model.Snapshot) {
		s.Guard.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `C:\Users\sam\Downloads\`}}
	}, "defender-exclusions:high"},
	{"Defender is told to skip every program file", func(s *model.Snapshot) { s.Guard.Exclusions = []model.Exclusion{{Kind: "File type", Value: ".exe"}} }, "defender-exclusions:high"},
	{"Defender is told to skip one harmless kind of file", func(s *model.Snapshot) { s.Guard.Exclusions = []model.Exclusion{{Kind: "File type", Value: "log"}} }, "defender-exclusions:medium"},
	{"the firewall is off on public networks", func(s *model.Snapshot) { s.Guard.FirewallHealth, s.Guard.Firewall[1].On = model.No, model.No }, "firewall-off:high"},
	{"the firewall is off and Windows Security gives no verdict", func(s *model.Snapshot) {
		s.Guard.FirewallHealth, s.Guard.FirewallProducts, s.Guard.Firewall[0].On = model.NotKnown, nil, model.No
	}, "firewall-off:high"},
	{"Windows Security says the firewall needs attention", func(s *model.Snapshot) { s.Guard.FirewallHealth = model.No }, "firewall-off:high"},
	{"another firewall has taken over from Windows Firewall", func(s *model.Snapshot) {
		s.Guard.FirewallProducts = []model.SecurityProduct{{Name: "Other Firewall", On: model.Yes}}
		for i := range s.Guard.Firewall {
			s.Guard.Firewall[i].On = model.No
		}
	}, ""},
	{"User Account Control is switched off", func(s *model.Snapshot) { s.Guard.UAC = model.No }, "uac-off:high"},
	{"User Account Control is set to never notify", func(s *model.Snapshot) { s.Guard.UACSilent = model.Yes }, "uac-off:medium"},
	{"Windows has not updated for two months", func(s *model.Snapshot) { s.Guard.LastUpdate = now.AddDate(0, 0, -60) }, "updates-old:medium"},
	{"Windows has not updated for most of a year", func(s *model.Snapshot) { s.Guard.LastUpdate = now.AddDate(0, 0, -200) }, "updates-old:high"},
	{"Windows updated five weeks ago", func(s *model.Snapshot) { s.Guard.LastUpdate = now.AddDate(0, 0, -35) }, ""},
	{"when Windows last updated is not known", func(s *model.Snapshot) { s.Guard.UpdateKnown, s.Guard.LastUpdate = false, time.Time{} }, ""},
	{"the hosts file blocks an advertising site", func(s *model.Snapshot) {
		s.Guard.Hosts = append(s.Guard.Hosts, model.HostsEntry{Address: "0.0.0.0", Names: []string{"ads.example.com", "tracker.example.com"}})
	}, "hosts-entries:low"},
	{"the hosts file blocks Windows Update and an antivirus maker", func(s *model.Snapshot) {
		s.Guard.Hosts = append(s.Guard.Hosts, model.HostsEntry{Address: "127.0.0.1", Names: []string{"update.microsoft.com", "www.malwarebytes.com"}})
	}, "hosts-entries:high"},
	{"the hosts file sends a bank's name to another address", func(s *model.Snapshot) {
		s.Guard.Hosts = append(s.Guard.Hosts, model.HostsEntry{Address: "203.0.113.9", Names: []string{"bank.example.com"}})
	}, "hosts-entries:medium"},
	{"the hosts file holds the names a developer tool adds", func(s *model.Snapshot) {
		s.Guard.Hosts = append(s.Guard.Hosts, model.HostsEntry{Address: "192.168.1.5", Names: []string{"host.docker.internal", "gateway.docker.internal", "nas"}})
	}, "hosts-entries:low"},
	{"Windows is set to read its hosts file from somewhere else", func(s *model.Snapshot) { s.Guard.HostsPath = `C:\Users\sam\AppData\hosts` }, "hosts-entries:high"},
	{"the Windows disk is not encrypted", func(s *model.Snapshot) {
		s.Guard.Volumes[0] = model.Volume{Drive: "C:", Encrypted: model.No, State: "Off"}
	}, "disk-not-encrypted:low"},
	{"only a second disk is not encrypted", func(s *model.Snapshot) {
		s.Guard.Volumes = append(s.Guard.Volumes, model.Volume{Drive: "D:", Encrypted: model.No, State: "Off"})
	}, ""},
	{"Windows did not say whether the disk is encrypted", func(s *model.Snapshot) { s.Guard.Volumes[0] = model.Volume{Drive: "C:"} }, ""},
	{"Secure Boot is off", func(s *model.Snapshot) { s.Guard.SecureBoot = model.No }, "secure-boot-off:low"},
	{"a PC too old to have Secure Boot", func(s *model.Snapshot) { s.Guard.SecureBoot = model.NotKnown }, ""},

	// Accounts and remote access.
	{"Remote Desktop is switched on", func(s *model.Snapshot) { s.Guard.RemoteDesktop = model.Yes }, "remote-desktop-on:medium"},
	{"AnyDesk is running", run(model.Process{PID: 9000, Name: "AnyDesk.exe", File: signed(`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`, "AnyDesk Software GmbH")}), "remote-tool:medium"},
	{"AnyDesk is installed but neither running nor set to start", func(s *model.Snapshot) {
		s.Guard.Programs = append(s.Guard.Programs, model.Installed{Name: "AnyDesk"})
	}, "remote-tool:low"},
	{"TeamViewer's service starts with Windows", add(entry(model.Service, "TeamViewer", signed(`C:\Program Files\TeamViewer\TeamViewer_Service.exe`, "TeamViewer Germany GmbH"))), "remote-tool:medium"},
	{"a remote-control service is running inside a shared host", func(s *model.Snapshot) { s.Processes[1].Services = append(s.Processes[1].Services, "sshd") }, "remote-tool:medium"},
	{"Quick Assist, which comes with Windows, is open", run(model.Process{PID: 9000, Name: "quickassist.exe", File: windows(`C:\Windows\System32\quickassist.exe`)}), "remote-tool:medium"},
	{"the Guest account is switched on", func(s *model.Snapshot) { s.Guard.Guest = model.Yes }, "guest-on:medium"},
	{"Windows signs in by itself", func(s *model.Snapshot) { s.Guard.AutoSignIn, s.Guard.AutoUser = model.Yes, "sam" }, "auto-sign-in:medium"},
	{"the built-in Administrator account is switched on", func(s *model.Snapshot) { s.Guard.Admins[0].Disabled = model.No }, "builtin-administrator-on:low"},
}

// Each change is made to a fresh healthy PC, and must flag exactly what it
// says: nothing less, and nothing else.
func TestRules(t *testing.T) {
	fired := map[string]bool{}
	for _, c := range changes {
		s := healthy()
		c.do(s)
		findings := Check(s)
		if got := outcome(findings); got != c.want {
			t.Errorf("%s:\n   got %q\n  want %q", c.name, got, c.want)
		}
		for _, f := range findings {
			fired[f.Rule] = true
			checkWording(t, c.name, f)
		}
	}
	// A rule that no test can make fire is a rule nobody has checked.
	for _, rule := range All() {
		if !fired[rule.ID] {
			t.Errorf("no test makes the rule %s fire", rule.ID)
		}
	}
}

// checkWording holds every finding to the promises the program makes: it
// explains itself, it says what to do, and it never calls anything a virus.
func checkWording(t *testing.T, name string, f Finding) {
	t.Helper()
	for part, text := range map[string]string{"title": f.Title, "subject": f.Subject, "reason": f.Reason, "advice": f.Advice} {
		if strings.TrimSpace(text) == "" {
			t.Errorf("%s: the finding %s has no %s", name, f.Rule, part)
		}
		lower := strings.ToLower(text)
		if strings.Contains(strings.NewReplacer("antivirus", "", "virus and threat protection", "").Replace(lower), "virus") || strings.Contains(lower, "infected") || strings.Contains(lower, "infection") {
			t.Errorf("%s: the %s of %s gives a verdict instead of a reason: %q", name, part, f.Rule, text)
		}
		if strings.ContainsAny(text, "\u2014\u2013") {
			t.Errorf("%s: the %s of %s uses a long dash: %q", name, part, f.Rule, text)
		}
	}
	for _, text := range []string{f.Reason, f.Advice} {
		if !strings.HasSuffix(text, ".") && !strings.HasSuffix(text, `."`) {
			t.Errorf("%s: a sentence of %s does not end properly: %q", name, f.Rule, text)
		}
		if strings.Contains(text, "  ") {
			t.Errorf("%s: a sentence of %s has a double space: %q", name, f.Rule, text)
		}
	}
	if f.Ref == "" {
		t.Errorf("%s: the finding %s does not say which item it is about", name, f.Rule)
	}
	for _, fact := range f.Facts {
		if fact.Label == "" || fact.Value == "" {
			t.Errorf("%s: the finding %s carries an empty fact: %+v", name, f.Rule, fact)
		}
	}
}

func TestEveryRuleIsDescribed(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range All() {
		if rule.ID == "" || rule.Title == "" || rule.Why == "" || rule.check == nil {
			t.Errorf("the rule %q is missing its name, title, reason or check", rule.ID)
		}
		if seen[rule.ID] {
			t.Errorf("two rules are called %s", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Area < 0 || rule.Area >= model.Areas {
			t.Errorf("the rule %s belongs to no area", rule.ID)
		}
		if strings.Contains(strings.ReplaceAll(strings.ToLower(rule.Title+rule.Why), "antivirus", ""), "virus") {
			t.Errorf("the rule %s talks of a virus", rule.ID)
		}
	}
}

func TestMostSeriousFirst(t *testing.T) {
	s := healthy()
	s.Guard.SecureBoot = model.No                                                                   // good to know
	s.Guard.RemoteDesktop = model.Yes                                                               // worth a look
	s.Startup = append(s.Startup, entry(model.RunKey, "Host", windows(`C:\ProgramData\lsass.exe`))) // look first
	s.Guard.UAC = model.No                                                                          // look first
	findings := Check(s)
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4: %s", len(findings), outcome(findings))
	}
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > findings[i-1].Severity {
			t.Errorf("finding %d (%s) is more serious than the one before it", i, findings[i].Rule)
		}
	}
	// Within one severity, the areas come in the order of the lights.
	if findings[0].Area != model.Protection || findings[1].Area != model.StartsWithWindows {
		t.Errorf("the two serious findings are in the order %v, %v", findings[0].Area, findings[1].Area)
	}
}

func TestLights(t *testing.T) {
	s := healthy()
	s.Guard.SecureBoot = model.No                                                                          // good to know: stays green
	s.Startup = append(s.Startup, entry(model.RunKey, "Tool", unsigned(`C:\Program Files\Tool\tool.exe`))) // worth a look: amber
	s.Processes = append(s.Processes, model.Process{PID: 9000, Name: "svchost.exe", File: windows(`C:\Users\sam\svchost.exe`)})
	s.Guard.RemoteDesktop = model.Yes
	findings := Check(s)
	lights := Lights(s, findings)
	want := [model.Areas]Light{model.Protection: Green, model.StartsWithWindows: Amber, model.RunningNow: Red, model.Connections: Green, model.Accounts: Amber}
	if lights != want {
		t.Errorf("got %v, want %v", lights, want)
	}
	if high, medium, low := Count(findings, model.Protection); high != 0 || medium != 0 || low != 1 {
		t.Errorf("protection counts %d, %d, %d; want 0, 0, 1", high, medium, low)
	}
	// A serious finding is not painted over by a lesser one that comes later.
	s.Processes = append(s.Processes, model.Process{PID: 9001, Name: "setup.exe", File: signed(`C:\Users\sam\Downloads\setup.exe`, "Notes Ltd")})
	if lights := Lights(s, Check(s)); lights[model.RunningNow] != Red {
		t.Errorf("running now shows %v, want red", lights[model.RunningNow])
	}
	// What could not be read is grey, not green.
	empty := &model.Snapshot{Taken: now, Folders: folders}
	for area, light := range Lights(empty, Check(empty)) {
		if light != Grey {
			t.Errorf("%s shows %v with nothing read, want grey", model.Area(area), light)
		}
	}
	for _, light := range []Light{Grey, Green, Amber, Red} {
		if light.String() == "" {
			t.Errorf("light %d has no words", light)
		}
	}
}

// The remote-control list is also shown as plain facts, apart from the rule.
func TestRemoteTools(t *testing.T) {
	s := healthy()
	if tools := RemoteTools(s); len(tools) != 0 {
		t.Errorf("a PC with a VPN and a note-taking app has remote-control software: %+v", tools)
	}
	s.Guard.Programs = append(s.Guard.Programs, model.Installed{Name: "TeamViewer 15"}, model.Installed{Name: "AnyDesk"})
	s.Processes = append(s.Processes, model.Process{PID: 9000, Name: "AnyDesk.exe", Services: []string{"AnyDesk"}}, model.Process{PID: 9001, Name: "AnyDesk.exe"})
	s.Startup = append(s.Startup, entry(model.StartupFolder, "AnyDesk.lnk", signed(`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`, "AnyDesk Software GmbH")))
	tools := RemoteTools(s)
	if len(tools) != 2 || tools[0].Name != "AnyDesk" || tools[1].Name != "TeamViewer" {
		t.Fatalf("got %+v, want AnyDesk (running) before TeamViewer", tools)
	}
	if a := tools[0]; !a.Running || !a.Starts || !a.Installed || len(a.Evidence) != 4 {
		t.Errorf("AnyDesk: %+v", a)
	}
	if tv := tools[1]; tv.Running || tv.Starts || !tv.Installed {
		t.Errorf("TeamViewer: %+v", tv)
	}
	// Windows Remote Management is part of Windows, so it only counts when it runs.
	s = healthy()
	s.Startup = append(s.Startup, entry(model.Service, "WinRM", windows(`C:\Windows\System32\svchost.exe`)))
	if tools := RemoteTools(s); len(tools) != 0 {
		t.Errorf("a stopped part of Windows was reported: %+v", tools)
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := list([]string{"a", "b", "c"}, 3); got != "a, b, c" {
		t.Errorf("got %q", got)
	}
	if got := list([]string{"a", "b", "c", "d"}, 2); got != "a, b and 2 others" {
		t.Errorf("got %q", got)
	}
	if got := list([]string{"a", "b", "c"}, 2); got != "a, b and 1 other" {
		t.Errorf("got %q", got)
	}
	if plural(1, "site", "sites") != "1 site" || plural(3, "site", "sites") != "3 sites" || plural(0, "site", "sites") != "0 sites" {
		t.Error("plural counts wrongly")
	}
	for _, severity := range []Severity{Low, Medium, High} {
		if severity.String() == "" {
			t.Errorf("severity %d has no words", severity)
		}
	}
}
