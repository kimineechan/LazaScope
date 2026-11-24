// Package sample holds a made-up PC. LazaScope shows it when started with
// --demo, so that anyone can see what findings look like without having
// any, and the pictures in the documentation show nobody's real computer.
//
// The PC is invented, and so are the makers Northwind, Brightline, Contoso
// and Fabrikam. It has a few honest oddities and two planted ones: a
// program that borrows the name of a part of Windows, and a scheduled task
// with a scrambled command. Its logs tell the rest of the story: what the
// antivirus stopped, which folder it was then told to skip, and a memory
// module that has begun to fail.
package sample

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
	"lazascope/internal/wallets"
)

const (
	windowsFolder = `C:\Windows`
	system        = `C:\Windows\System32\`
	profile       = `C:\Users\sam`
)

func signed(path, signer, says string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Company: signer, Description: says, Version: "1.0.0.0",
		Signature: sigcheck.Result{Status: sigcheck.Signed, Source: sigcheck.Embedded, Signer: signer}}
}

// part is a file that belongs to Windows, signed through a catalogue as
// most of them are.
func part(path, says string) model.File {
	file := signed(path, "Microsoft Windows", says)
	file.Company, file.Version = "Microsoft Corporation", "10.0.26100.2314"
	file.Signature.Source, file.Signature.Catalogue = sigcheck.Catalogue, "Microsoft-Windows-Client-Desktop-Required-Package.cat"
	return file
}

func unsigned(path, company, says string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Company: company, Description: says, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}
}

func entry(kind model.StartupKind, name, where, command string, file model.File) model.Startup {
	return model.Startup{Kind: kind, Name: name, Where: where, Command: command, Program: file, Target: file, Enabled: true, AllUsers: kind != model.RunKey}
}

const (
	runUser    = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	runMachine = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	services   = `HKLM\SYSTEM\CurrentControlSet\Services\`
	scheduler  = "Task Scheduler"

	startupFolder = profile + `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
	hidden        = `powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQA`
)

// service is a Windows service that runs inside the shared host program.
func service(name, title, library, account, about string) model.Startup {
	return model.Startup{Kind: model.Service, Name: name, Title: title, Where: services + name, AllUsers: true, Enabled: true, Running: true,
		Command: system + `svchost.exe -k netsvcs -p`, Program: part(system+"svchost.exe", "Host Process for Windows Services"), Target: part(system+library, title),
		Account: account, Trigger: "When Windows starts", Description: about}
}

func driver(name, title, path string, file model.File) model.Startup {
	return model.Startup{Kind: model.Driver, Name: name, Title: title, Where: services + name, AllUsers: true, Enabled: true, Running: true,
		Command: path, Program: file, Target: file, Trigger: "While Windows is loading"}
}

func task(name, command, trigger, account string, program, target model.File) model.Startup {
	return model.Startup{Kind: model.ScheduledTask, Name: name, Where: scheduler, AllUsers: true, Enabled: true, Command: command, Program: program, Target: target, Trigger: trigger, Account: account}
}

// Phrases returns what the search for recovery phrases finds on the
// made-up PC: a phrase saved in the Documents folder, which OneDrive copies,
// a run of recovery words in a note on the Desktop, and the word list that
// a downloaded wallet kit carries.
func Phrases() *model.PhraseSearch {
	return &model.PhraseSearch{
		When: time.Now(), Folders: []string{profile + `\Desktop`, profile + `\OneDrive\Documents`, profile + `\Downloads`},
		Read: 1873, Cloud: 41, Big: 2,
		Found: []model.PhraseFile{
			{Path: profile + `\OneDrive\Documents\wallet backup.txt`, Runs: 1, Lines: []int{3}, Words: 12, Phrase: 12},
			{Path: profile + `\Desktop\stream notes.md`, Runs: 1, Lines: []int{14}, Words: 13},
			{Path: profile + `\Downloads\WalletKit\assets\english.txt`, Runs: 1, Lines: []int{1}, List: true},
		},
	}
}

// PC returns the made-up PC, as if looked at just now.
func PC() *model.Snapshot {
	now := time.Now()
	s := &model.Snapshot{
		Taken: now, Took: 1900 * time.Millisecond, Computer: "STUDY-PC", User: "sam", Windows: "Windows 11 Home 24H2",
		Folders: model.Folders{Windows: windowsFolder, System: `C:\Windows\System32`, ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`,
			ProgramData: `C:\ProgramData`, Users: `C:\Users`, Profile: profile, Temp: profile + `\AppData\Local\Temp`, Downloads: profile + `\Downloads`},
	}

	explorer := part(windowsFolder+`\explorer.exe`, "Windows Explorer")
	edge := signed(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, "Microsoft Corporation", "Microsoft Edge")
	notes := signed(`C:\Program Files\Brightline Notes\notes.exe`, "Brightline Software Ltd", "Brightline Notes")
	audio := signed(`C:\Program Files\Northwind\Audio\NwAudioTray.exe`, "Northwind Audio Ltd", "Northwind Audio Console")
	cloud := signed(profile+`\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, "Microsoft Corporation", "Microsoft OneDrive")
	anydesk := signed(`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`, "AnyDesk Software GmbH", "AnyDesk")
	sorter := unsigned(`C:\Program Files\PhotoSorter\PhotoSorter.exe`, "PhotoSorter contributors", "PhotoSorter")
	setup := signed(profile+`\Downloads\FabrikamLauncherSetup.exe`, "Fabrikam Games Inc.", "Fabrikam Launcher Setup")
	setup.Modified = now.Add(-26 * time.Hour)
	setup.Origin = &model.Origin{Zone: 3, Host: "https://downloads.fabrikam.example/launcher/FabrikamLauncherSetup.exe", Referrer: "https://www.fabrikam.example/download"}
	impostor := unsigned(profile+`\AppData\Roaming\svchost.exe`, "", "")
	shell := part(system+`WindowsPowerShell\v1.0\powershell.exe`, "Windows PowerShell")
	svchost := part(system+"svchost.exe", "Host Process for Windows Services")

	off := entry(model.RunKey, "FabrikamLauncher", runUser, `"C:\Program Files\Fabrikam\Launcher\launcher.exe" --silent`, signed(`C:\Program Files\Fabrikam\Launcher\launcher.exe`, "Fabrikam Games Inc.", "Fabrikam Launcher"))
	off.Enabled = false
	gone := entry(model.RunKey, "ContosoPrintTool", runMachine, `"C:\Program Files\Contoso\Print\tool.exe" /tray`, model.File{Path: `C:\Program Files\Contoso\Print\tool.exe`})
	shellSetting := model.Startup{Kind: model.LogonSetting, Name: "Shell", Where: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, AllUsers: true, Enabled: true,
		Command: "explorer.exe", Program: explorer, Target: explorer, Trigger: "When someone signs in"}
	userinit := part(system+"userinit.exe", "Userinit Logon Application")
	userinitSetting := shellSetting
	userinitSetting.Name, userinitSetting.Command, userinitSetting.Program, userinitSetting.Target = "Userinit", system+"userinit.exe", userinit, userinit
	desk := entry(model.Service, "AnyDesk", services+"AnyDesk", `"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service`, anydesk)
	desk.Title, desk.Running, desk.Account, desk.Trigger = "AnyDesk Service", true, "SYSTEM", "When Windows starts"
	spool := entry(model.Service, "ContosoSpool", services+"ContosoSpool", `"C:\Program Files\Contoso\Print\spool.exe"`, signed(`C:\Program Files\Contoso\Print\spool.exe`, "Contoso Print Ltd", "Contoso Print Service"))
	spool.Title, spool.Running, spool.Account, spool.Trigger = "Contoso Print Service", true, "SYSTEM", "When Windows starts"

	// A batch file the owner wrote to open a few things at sign-in: flagged,
	// and harmless. It shows that worth a look does not mean something is wrong.
	own := entry(model.StartupFolder, "Open study apps.cmd", startupFolder, startupFolder+`\Open study apps.cmd`, model.File{Path: startupFolder + `\Open study apps.cmd`, Exists: true, Size: 212})
	own.AllUsers = false
	// What the batch file says, as LazaScope would read it from the disk.
	own.Target.Script = &model.Script{Lines: []string{`@echo off`, `rem Opens what I need for studying, so I do not have to each morning.`, `start "" "C:\Program Files\Brightline\Notes\notes.exe"`, `start "" https://library.example.ac.uk/`, `del /q "%TEMP%\study-*.tmp"`}, Signs: []string{"It deletes files or folders."}}
	own.Program = own.Target

	s.Startup = []model.Startup{
		entry(model.RunKey, "SecurityHealth", runMachine, `%windir%\system32\SecurityHealthSystray.exe`, part(system+"SecurityHealthSystray.exe", "Windows Security notification icon")),
		entry(model.RunKey, "NorthwindAudio", runMachine, `"C:\Program Files\Northwind\Audio\NwAudioTray.exe" -background`, audio),
		entry(model.RunKey, "OneDrive", runUser, `"`+cloud.Path+`" /background`, cloud),
		entry(model.RunKey, "Brightline Notes", runUser, `"C:\Program Files\Brightline Notes\notes.exe" --minimised`, notes),
		entry(model.RunKey, "PhotoSorter", runUser, `"C:\Program Files\PhotoSorter\PhotoSorter.exe" /watch`, sorter),
		entry(model.RunKey, "Windows Host Service", runUser, impostor.Path, impostor),
		off, gone,
		entry(model.StartupFolder, "AnyDesk.lnk", `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`, `"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --control`, anydesk),
		own,
		task(`\Microsoft\Windows\Defrag\ScheduledDefrag`, system+`defrag.exe -c -h -o`, "Weekly", "SYSTEM", part(system+"defrag.exe", "Disk Defragmenter Module"), part(system+"defrag.exe", "Disk Defragmenter Module")),
		task(`\Microsoft\Windows\UpdateOrchestrator\Schedule Scan`, system+`usoclient.exe StartScan`, "Daily", "SYSTEM", part(system+"usoclient.exe", "UsoClient"), part(system+"usoclient.exe", "UsoClient")),
		task(`\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan`, `"C:\Program Files\Windows Defender\MpCmdRun.exe" Scan -ScheduleJob`, "Daily", "SYSTEM",
			signed(`C:\Program Files\Windows Defender\MpCmdRun.exe`, "Microsoft Windows Publisher", "Microsoft Malware Protection Command Line Utility"), signed(`C:\Program Files\Windows Defender\MpCmdRun.exe`, "Microsoft Windows Publisher", "Microsoft Malware Protection Command Line Utility")),
		task(`\MicrosoftEdgeUpdateTaskMachineCore`, `"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c`, "When someone signs in; Daily", "SYSTEM",
			signed(`C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`, "Microsoft Corporation", "Microsoft Edge Update"), signed(`C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`, "Microsoft Corporation", "Microsoft Edge Update")),
		task(`\OneDrive Standalone Update Task`, `%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`, "Daily", "sam",
			signed(profile+`\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`, "Microsoft Corporation", "Standalone Updater"), signed(profile+`\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`, "Microsoft Corporation", "Standalone Updater")),
		task(`\Brightline\Notes Update`, `"C:\Program Files\Brightline Notes\update.exe" /quiet`, "Daily", "SYSTEM",
			signed(`C:\Program Files\Brightline Notes\update.exe`, "Brightline Software Ltd", "Brightline Updater"), signed(`C:\Program Files\Brightline Notes\update.exe`, "Brightline Software Ltd", "Brightline Updater")),
		task(`\Updater\Check`, hidden, "When someone signs in, then every 1 hour", "sam", shell, shell),
		service("Audiosrv", "Windows Audio", "audiosrv.dll", "LOCAL SERVICE", "Manages audio for Windows-based programs."),
		service("Dhcp", "DHCP Client", "dhcpcore.dll", "LOCAL SERVICE", "Registers and updates the address this PC is given on a network."),
		service("Dnscache", "DNS Client", "dnsrslvr.dll", "NETWORK SERVICE", "Remembers the addresses of websites that have been looked up."),
		service("EventLog", "Windows Event Log", "wevtsvc.dll", "LOCAL SERVICE", "Keeps the logs of what happens on the PC."),
		service("mpssvc", "Windows Defender Firewall", "mpssvc.dll", "LOCAL SERVICE", "Blocks connections that no rule allows."),
		service("Schedule", "Task Scheduler", "schedsvc.dll", "SYSTEM", "Starts tasks at set times."),
		service("wuauserv", "Windows Update", "wuaueng.dll", "SYSTEM", "Finds, downloads and installs updates for Windows."),
		desk, spool,
		driver("disk", "Disk Driver", system+`drivers\disk.sys`, part(system+`drivers\disk.sys`, "PnP Disk Driver")),
		driver("Ntfs", "NTFS", system+`drivers\ntfs.sys`, part(system+`drivers\ntfs.sys`, "NT File System Driver")),
		driver("tcpip", "TCP/IP Protocol Driver", system+`drivers\tcpip.sys`, part(system+`drivers\tcpip.sys`, "TCP/IP Driver")),
		driver("NwAudio", "Northwind Audio Device", system+`drivers\nwaudio.sys`, signed(system+`drivers\nwaudio.sys`, "Microsoft Windows Hardware Compatibility Publisher", "Northwind Audio Driver")),
		shellSetting, userinitSetting,
	}

	started := func(minutes int) time.Time { return now.Add(-time.Duration(minutes) * time.Minute) }
	process := func(pid, parent uint32, name string, file model.File, user, command string, minutes int, services ...string) model.Process {
		p := model.Process{PID: pid, Parent: parent, Name: name, File: file, User: user, Command: command, Session: 1, Started: started(minutes), Services: services}
		if user != "sam" && file.Path != "" {
			p.CommandHidden, p.Command, p.Session = true, "", 0
		}
		return p
	}
	s.Processes = []model.Process{
		{PID: 4, Name: "System", User: "SYSTEM", Started: started(600)},
		{PID: 140, Parent: 4, Name: "Registry", User: "SYSTEM", Started: started(600)},
		process(520, 4, "smss.exe", part(system+"smss.exe", "Windows Session Manager"), "SYSTEM", "", 600),
		process(760, 0, "csrss.exe", part(system+"csrss.exe", "Client Server Runtime Process"), "SYSTEM", "", 600),
		process(840, 0, "wininit.exe", part(system+"wininit.exe", "Windows Start-Up Application"), "SYSTEM", "", 600),
		process(980, 840, "services.exe", part(system+"services.exe", "Services and Controller app"), "SYSTEM", "", 600),
		process(1000, 840, "lsass.exe", part(system+"lsass.exe", "Local Security Authority Process"), "SYSTEM", "", 600),
		process(1180, 980, "svchost.exe", svchost, "SYSTEM", "", 600, "Schedule", "wuauserv"),
		process(1260, 980, "svchost.exe", svchost, "LOCAL SERVICE", "", 600, "Audiosrv", "Dhcp", "EventLog"),
		process(1340, 980, "svchost.exe", svchost, "NETWORK SERVICE", "", 600, "Dnscache"),
		process(1420, 980, "svchost.exe", svchost, "LOCAL SERVICE", "", 600, "mpssvc"),
		process(2100, 980, "spool.exe", signed(`C:\Program Files\Contoso\Print\spool.exe`, "Contoso Print Ltd", "Contoso Print Service"), "SYSTEM", "", 598, "ContosoSpool"),
		process(2240, 980, "AnyDesk.exe", anydesk, "SYSTEM", "", 598, "AnyDesk"),
		process(2400, 980, "MsMpEng.exe", signed(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`, "Microsoft Windows Publisher", "Antimalware Service Executable"), "SYSTEM", "", 598),
		process(3000, 0, "explorer.exe", explorer, "sam", windowsFolder+`\explorer.exe`, 540),
		process(3180, 3000, "SecurityHealthSystray.exe", part(system+"SecurityHealthSystray.exe", "Windows Security notification icon"), "sam", `"`+system+`SecurityHealthSystray.exe"`, 539),
		process(3260, 3000, "NwAudioTray.exe", audio, "sam", `"C:\Program Files\Northwind\Audio\NwAudioTray.exe" -background`, 539),
		process(3340, 3000, "OneDrive.exe", cloud, "sam", `"`+cloud.Path+`" /background`, 539),
		process(3420, 3000, "notes.exe", notes, "sam", `"C:\Program Files\Brightline Notes\notes.exe" --minimised`, 539),
		process(3500, 3000, "PhotoSorter.exe", sorter, "sam", `"C:\Program Files\PhotoSorter\PhotoSorter.exe" /watch`, 539),
		process(3580, 3000, "AnyDesk.exe", anydesk, "sam", `"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --control`, 539),
		process(4200, 3000, "msedge.exe", edge, "sam", `"`+edge.Path+`"`, 95),
		process(4260, 4200, "msedge.exe", edge, "sam", `"`+edge.Path+`" --type=gpu-process`, 95),
		process(4320, 4200, "msedge.exe", edge, "sam", `"`+edge.Path+`" --type=utility --utility-sub-type=network.mojom.NetworkService`, 95),
		process(4380, 4200, "msedge.exe", edge, "sam", `"`+edge.Path+`" --type=renderer`, 94),
		process(4440, 4200, "msedge.exe", edge, "sam", `"`+edge.Path+`" --type=renderer`, 40),
		process(5600, 4200, "FabrikamLauncherSetup.exe", setup, "sam", `"`+setup.Path+`"`, 3),
	}

	connection := func(pid uint32, name string, file model.File, remote string, port int, services ...string) model.Connection {
		return model.Connection{Protocol: "TCP", State: "Connected", Local: "192.168.1.24", LocalPort: 50000 + int(pid)%900 + port%90, Remote: remote, RemotePort: port, Reach: model.Internet,
			PID: pid, Process: name, File: file, Services: services}
	}
	waits := func(protocol string, pid uint32, name string, file model.File, local string, port int, services ...string) model.Connection {
		c := model.Connection{Protocol: protocol, Listening: true, State: "Waiting for connections", Local: local, LocalPort: port, Reach: model.LocalNetwork, PID: pid, Process: name, File: file, Services: services}
		if protocol == "UDP" {
			c.State = "Open to receive"
		}
		if local == "127.0.0.1" {
			c.Reach = model.ThisPC
		}
		return c
	}
	printer := connection(2100, "spool.exe", signed(`C:\Program Files\Contoso\Print\spool.exe`, "Contoso Print Ltd", "Contoso Print Service"), "192.168.1.60", 9100, "ContosoSpool")
	printer.Reach = model.LocalNetwork
	s.Connections = []model.Connection{
		connection(4320, "msedge.exe", edge, "203.0.113.80", 443),
		connection(4320, "msedge.exe", edge, "203.0.113.81", 443),
		connection(4320, "msedge.exe", edge, "198.51.100.14", 443),
		connection(3340, "OneDrive.exe", cloud, "198.51.100.77", 443),
		connection(3420, "notes.exe", notes, "203.0.113.25", 443),
		connection(2240, "AnyDesk.exe", anydesk, "198.51.100.200", 443, "AnyDesk"),
		connection(1180, "svchost.exe", svchost, "198.51.100.9", 443, "Schedule", "wuauserv"),
		printer,
		waits("TCP", 4, "System", model.File{}, "0.0.0.0", 445),
		waits("TCP", 1260, "svchost.exe", svchost, "0.0.0.0", 135, "Audiosrv", "Dhcp", "EventLog"),
		waits("TCP", 2240, "AnyDesk.exe", anydesk, "0.0.0.0", 7070, "AnyDesk"),
		waits("TCP", 3420, "notes.exe", notes, "127.0.0.1", 49320),
		waits("TCP", 3500, "PhotoSorter.exe", sorter, "127.0.0.1", 8750),
		waits("UDP", 1340, "svchost.exe", svchost, "0.0.0.0", 5353, "Dnscache"),
		waits("UDP", 1260, "svchost.exe", svchost, "0.0.0.0", 68, "Audiosrv", "Dhcp", "EventLog"),
		waits("UDP", 4320, "msedge.exe", edge, "0.0.0.0", 5353),
	}

	s.Guard = model.Guard{
		Antivirus:        []model.SecurityProduct{{Name: "Microsoft Defender Antivirus", On: model.Yes, UpToDate: model.Yes}},
		AntivirusHealth:  model.Yes,
		FirewallHealth:   model.Yes,
		FirewallProducts: []model.SecurityProduct{{Name: "Windows Firewall", On: model.Yes}},
		Firewall:         []model.FirewallProfile{{Name: "Private networks", On: model.Yes}, {Name: "Public networks", On: model.Yes}, {Name: "Work networks", On: model.Yes}},
		RealTime:         model.Yes, Tamper: model.Yes,
		UAC: model.Yes, UACSilent: model.No, Build: "26100.2314", LastUpdate: now.AddDate(0, 0, -71), UpdateKnown: true,
		Volumes: []model.Volume{{Drive: "C:", Encrypted: model.No, State: "Off"}}, SecureBoot: model.Yes,
		RemoteDesktop: model.No, RemoteNLA: model.Yes, AdminsVisible: true, Guest: model.No, AutoSignIn: model.No,
		Admins:    []model.Account{{Name: "Administrator", BuiltIn: "Administrator", Disabled: model.Yes}, {Name: "sam", Disabled: model.No}},
		HostsPath: `C:\Windows\System32\drivers\etc\hosts`, HostsVisible: true,
		Hosts: []model.HostsEntry{{Address: "127.0.0.1", Names: []string{"localhost"}}, {Address: "0.0.0.0", Names: []string{"ads.example.net", "tracker.example.net"}}},
		Programs: []model.Installed{{Name: "AnyDesk", Publisher: "AnyDesk Software GmbH"}, {Name: "Brightline Notes", Publisher: "Brightline Software Ltd"},
			{Name: "Contoso Print Suite", Publisher: "Contoso Print Ltd"}, {Name: "Microsoft Edge", Publisher: "Microsoft Corporation"},
			{Name: "Northwind Audio Console", Publisher: "Northwind Audio Ltd"}, {Name: "PhotoSorter"}},
	}
	// What the PC's own logs hold. Defender stopped a download twelve days
	// ago, and its log shows the impostor's folder being added to the list
	// of places it skips. The memory has begun to report errors, and
	// Windows has stopped twice.
	s.Startup = append(s.Startup,
		model.Startup{Kind: model.BrowserExtension, Name: "uBlock Origin", Where: "Firefox, profile default-release", Enabled: true, Trigger: "Whenever Firefox is open",
			Description: "Finally, an efficient blocker. Easy on CPU and memory.",
			Extension: &model.Extension{Browser: "Firefox", Profile: "default-release", ID: "uBlock0@raymondhill.net", Name: "uBlock Origin", Version: "1.62.0", Enabled: true,
				Source: model.FromStore, EverySite: true, May: []string{"watch web traffic as it passes", "see the addresses of the pages you have open"}}},
		model.Startup{Kind: model.BrowserExtension, Name: "Shopping Helper Pro", Where: "Microsoft Edge, profile Default", Enabled: true, Trigger: "Whenever Microsoft Edge is open",
			Description: "Finds you the best deals while you browse.",
			Extension: &model.Extension{Browser: "Microsoft Edge", Profile: "Default", ID: "kjdnpgcaeoblhikmnpiklmnopqrstuvw", Name: "Shopping Helper Pro", Version: "3.4.1", Enabled: true,
				Source: model.FromOutside, EverySite: true, May: []string{"read the cookies that keep you signed in", "see the addresses of the pages you have open"},
				Folder: profile + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions\\kjdnpgcaeoblhikmnpiklmnopqrstuvw\\3.4.1_0"}})
	s.Engine = "Microsoft Defender Antivirus"
	for i := range s.Startup {
		switch e := &s.Startup[i]; {
		case e.Name == "Open study apps.cmd":
			e.Target.Opinion, e.Program.Opinion = model.Opinion{Asked: true}, model.Opinion{Asked: true}
		case e.Command == hidden:
			e.Said = model.Opinion{Asked: true, Harmful: true, Name: "TrojanDownloader:PowerShell/Example.A!amsi"}
		}
	}
	// What VirusTotal said, as if a key had been set up and the programs
	// looked up two hours ago. The fingerprints and the engines are made up.
	s.Fingerprints, s.VirusTotal = map[string]string{}, map[string]model.Reputation{}
	lookedUp := func(f model.File, r model.Reputation) {
		sum := sha256.Sum256([]byte("LazaScope made-up file: " + f.Path))
		print := hex.EncodeToString(sum[:])
		s.Fingerprints[strings.ToLower(f.Path)] = print
		r.Asked = now.Add(-2 * time.Hour)
		s.VirusTotal[print] = r
	}
	lookedUp(impostor, model.Reputation{Known: true, Malicious: 23, Suspicious: 2, Undetected: 46, Harmless: 1, Analysed: now.AddDate(0, 0, -4),
		Label: "trojan.fakesvc/example", Votes: -14, Kind: "Win32 EXE", KnownAs: "svchost.exe",
		Names: []model.EngineName{{Engine: "Contoso Defend", Name: "Trojan:Win32/FakeSvc.A"}, {Engine: "Fabrikam Shield", Name: "Win32.Trojan.FakeSvc"},
			{Engine: "Litware Antivirus", Name: "Trojan.Agent.Example"}, {Engine: "Northwind AV", Name: "Gen:Variant.FakeSvc.1"}, {Engine: "Tailspin Secure", Name: "Suspicious.Svc"}}})
	lookedUp(sorter, model.Reputation{Known: true, Suspicious: 1, Undetected: 69, Harmless: 1, Analysed: now.AddDate(0, 0, -20), Kind: "Win32 EXE", KnownAs: "PhotoSorter.exe",
		Names: []model.EngineName{{Engine: "Tailspin Secure", Name: "Heuristic.Unsigned.Generic"}}})
	lookedUp(anydesk, model.Reputation{Known: true, Undetected: 71, Harmless: 1, Analysed: now.AddDate(0, 0, -1), Kind: "Win32 EXE", KnownAs: "AnyDesk.exe"})
	lookedUp(setup, model.Reputation{})
	lookedUp(notes, model.Reputation{Known: true, Undetected: 70, Harmless: 2, Analysed: now.AddDate(0, 0, -9), Kind: "Win32 EXE", KnownAs: "notes.exe"})

	// The wallets: the real MetaMask in Chrome, a copy of it dressed up as
	// the real one in Edge, and Electrum's files in the account's folder.
	// Clipboard history is on, and OneDrive copies the Documents folder.
	s.Startup = append(s.Startup,
		model.Startup{Kind: model.BrowserExtension, Name: "MetaMask", Where: "Google Chrome, profile Default", Enabled: true, Trigger: "Whenever Google Chrome is open",
			Extension: &model.Extension{Browser: "Google Chrome", Profile: "Default", ID: "nkbihfbeogaeaoehlefnkodbefgpgknn", Name: "MetaMask", Version: "13.4.0", Enabled: true, Source: model.FromStore, EverySite: true}},
		model.Startup{Kind: model.BrowserExtension, Name: "MetaMask Wallet Pro", Where: "Microsoft Edge, profile Default", Enabled: true, Trigger: "Whenever Microsoft Edge is open",
			Description: "The secure way to keep your crypto. Restore your wallet in seconds.",
			Extension: &model.Extension{Browser: "Microsoft Edge", Profile: "Default", ID: "hkmhgjgkcdaobfmhlcpjdhmpaggpljnb", Name: "MetaMask Wallet Pro", Version: "1.0.3", Enabled: true,
				Source: model.FromStore, EverySite: true, May: []string{"read and change what you copy and paste"}}})
	s.Clouds = []model.CloudFolder{{Service: "OneDrive", Path: profile + `\OneDrive`}}
	s.Clipboard = model.ClipboardSettings{Read: true, History: model.Yes, Cloud: model.No}
	s.Wallets = wallets.Inventory(s, []model.Wallet{{Name: "Electrum", Kind: "Wallet files", Where: profile + `\AppData\Roaming\Electrum\wallets`, Keys: true}})

	// The protections: PUA blocking, Controlled folder access, network
	// protection, memory integrity and LSA protection are off; no backup.
	s.Defences = []model.Defence{
		{Key: "pua", Name: "Potentially unwanted app blocking", On: model.No, Defender: true},
		{Key: "smartscreen", Name: "Check apps and files (SmartScreen)", On: model.Yes, Ransomware: true},
		{Key: "cfa", Name: "Controlled folder access", On: model.No, Defender: true, Ransomware: true},
		{Key: "network", Name: "Network protection", On: model.No, Defender: true, Ransomware: true},
		{Key: "cloud", Name: "Cloud-delivered protection", On: model.Yes, Defender: true, Ransomware: true},
		{Key: "hvci", Name: "Memory integrity", On: model.No},
		{Key: "lsa", Name: "Local Security Authority protection", On: model.No},
		{Key: "drivers", Name: "Microsoft Vulnerable Driver Blocklist", On: model.Yes},
	}
	// The camera app was used two days ago, and the impostor in the account's
	// folder used the microphone this morning.
	s.DeviceUses = []model.DeviceUse{
		{Device: "camera", App: "Microsoft.WindowsCamera_8wekyb3d8bbwe", Allowed: model.Yes, Start: now.AddDate(0, 0, -2), Stop: now.AddDate(0, 0, -2).Add(4 * time.Minute)},
		{Device: "microphone", App: impostor.Path, Program: true, Allowed: model.Yes, Start: now.Add(-6 * time.Hour), Stop: now.Add(-5 * time.Hour), File: impostor},
	}

	// What Windows remembers of programs this account opened.
	s.Ran = []model.Run{
		{Path: setup.Path, Source: "UserAssist", Count: 1, Last: now.Add(-25 * time.Hour), Focus: 2 * time.Minute},
		{Path: `C:\Program Files\PhotoSorter\PhotoSorter.exe`, Source: "UserAssist", Count: 31, Last: now.Add(-3 * time.Hour), Focus: 95 * time.Minute},
		{Path: "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App", Source: "UserAssist", Count: 4, Last: now.Add(-50 * time.Hour)},
	}

	s.Guard.NameServers, s.Guard.NameServersRead = []model.NameServer{{Address: "192.168.1.1", Connection: "Wi-Fi"}}, true
	s.Guard.Proxy = model.Proxy{Read: true}
	s.Guard.HistoryRead, s.Guard.HistoryDays = true, 90
	s.Guard.Detections = []model.Detection{{When: now.AddDate(0, 0, -12).Add(-3 * time.Hour), Threat: "Trojan:Win32/Wacatac.B!ml", Severity: "Severe", Category: "Trojan",
		Path: profile + `\Downloads\FreeVideoConverter_setup.exe`, Action: "Quarantine", Process: windowsFolder + `\explorer.exe`}}
	s.Guard.LoggedExclusions = []model.LoggedExclusion{{When: now.AddDate(0, 0, -12).Add(-2 * time.Hour), Exclusion: model.Exclusion{Kind: "Folder or file", Value: profile + `\AppData\Roaming`}}}
	memory := func(daysAgo int) model.Fault {
		return model.Fault{When: now.AddDate(0, 0, -daysAgo).Add(-5 * time.Hour), Part: "the memory", ID: 47,
			Words: "A corrected hardware error has occurred. Component: Memory. Error Source: Corrected Machine Check."}
	}
	s.Condition = model.Condition{
		Read: true, Days: 90, Retries: 1, Started: now.Add(-52 * time.Hour),
		Hardware:  []model.Fault{memory(2), memory(6), memory(6), memory(19)},
		Crashes:   []model.Crash{{When: now.AddDate(0, 0, -6).Add(-4 * time.Hour), Code: 0x1A, Name: "MEMORY_MANAGEMENT"}, {When: now.AddDate(0, 0, -19).Add(-4 * time.Hour), Code: 0x50, Name: "PAGE_FAULT_IN_NONPAGED_AREA"}},
		PowerCuts: []time.Time{now.AddDate(0, 0, -33)},
		Drives:    []model.Drive{{Letter: "C:", Size: 237 << 30, Free: 41 << 30}},
	}
	s.Gaps = []model.Gap{
		{Area: model.Protection, What: "The list of folders and programs that Microsoft Defender skips can only be read with administrator rights."},
		{Area: model.StartsWithWindows, What: "Windows shows some scheduled tasks to administrators only, so they are missing from this list. There are usually a few dozen. Most are parts of Windows and of software updaters, but not always all. Look again as administrator to see them."},
		{Area: model.RunningNow, What: "The command lines of 11 programs that run as other accounts can only be read with administrator rights."},
	}
	return s
}
