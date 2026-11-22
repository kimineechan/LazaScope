package view

import (
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sigcheck"
)

var taken = time.Date(2026, 11, 22, 14, 2, 0, 0, time.UTC)

func signed(path, signer string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Description: "A program", Company: signer, Signature: sigcheck.Result{Status: sigcheck.Signed, Source: sigcheck.Embedded, Signer: signer}}
}

func unsigned(path string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}
}

func entry(kind model.StartupKind, name string, file model.File) model.Startup {
	return model.Startup{Kind: kind, Name: name, Where: "a made-up place", Command: file.Path, Program: file, Target: file, Enabled: true}
}

// pc is a made-up healthy PC.
func pc() *model.Snapshot {
	explorer := signed(`C:\Windows\explorer.exe`, "Microsoft Windows")
	notes := signed(`C:\Program Files\Notes\notes.exe`, "Notes Ltd")
	return &model.Snapshot{
		Taken: taken, Computer: "STUDY-PC", User: "sam", Windows: "Windows 10 Pro 22H2",
		Folders: model.Folders{Windows: `C:\Windows`, System: `C:\Windows\System32`, Users: `C:\Users`, Profile: `C:\Users\sam`, Temp: `C:\Users\sam\AppData\Local\Temp`, Downloads: `C:\Users\sam\Downloads`},
		Startup: []model.Startup{
			entry(model.RunKey, "Notes", notes),
			{Kind: model.Service, Name: "Audiosrv", Title: "Windows Audio", Where: `HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv`, Command: `C:\Windows\System32\svchost.exe -k audio`, Enabled: true, Running: true,
				Account: "LOCAL SERVICE", Trigger: "When Windows starts", Description: "Manages audio.",
				Program: signed(`C:\Windows\System32\svchost.exe`, "Microsoft Windows"), Target: signed(`C:\Windows\System32\audiosrv.dll`, "Microsoft Windows")},
			{Kind: model.ScheduledTask, Name: `\Microsoft\Windows\Thing\Task`, Where: "Task Scheduler", Command: "Windows component {1}", Enabled: true, Untraced: true},
		},
		Processes: []model.Process{
			{PID: 4, Name: "System", User: "SYSTEM"},
			{PID: 3000, Name: "explorer.exe", File: explorer, User: "sam", Command: `C:\Windows\explorer.exe`, Started: taken.Add(-time.Hour)},
			{PID: 3100, Parent: 3000, Name: "notes.exe", File: notes, User: "sam", Command: `"C:\Program Files\Notes\notes.exe"`, Started: taken.Add(-time.Minute)},
			{PID: 900, Parent: 4, Name: "svchost.exe", File: signed(`C:\Windows\System32\svchost.exe`, "Microsoft Windows"), Services: []string{"Audiosrv"}, CommandHidden: true},
		},
		Connections: []model.Connection{
			{Protocol: "TCP", State: "Connected", Local: "192.168.1.20", LocalPort: 50000, Remote: "93.184.216.34", RemotePort: 443, Reach: model.Internet, PID: 3100, Process: "notes.exe", File: notes},
			{Protocol: "TCP", Listening: true, State: "Waiting for connections", Local: "0.0.0.0", LocalPort: 445, Reach: model.LocalNetwork, PID: 4, Process: "System"},
			{Protocol: "UDP", Listening: true, State: "Open to receive", Local: "127.0.0.1", LocalPort: 5000, Reach: model.ThisPC, PID: 3100, Process: "notes.exe", File: notes},
		},
		Guard: model.Guard{
			Antivirus:       []model.SecurityProduct{{Name: "Microsoft Defender Antivirus", On: model.Yes, UpToDate: model.Yes}},
			AntivirusHealth: model.Yes, FirewallHealth: model.Yes,
			Firewall: []model.FirewallProfile{{Name: "Private networks", On: model.Yes}, {Name: "Public networks", On: model.Yes}},
			RealTime: model.Yes, Tamper: model.Yes, ExclusionsVisible: true, UAC: model.Yes, UACSilent: model.No,
			Build: "19045.6036", LastUpdate: taken.AddDate(0, 0, -9), UpdateKnown: true,
			Volumes: []model.Volume{{Drive: "C:", Encrypted: model.Yes, State: "On"}}, SecureBoot: model.Yes,
			RemoteDesktop: model.No, Guest: model.No, AutoSignIn: model.No, AdminsVisible: true,
			Admins:    []model.Account{{Name: "Administrator", BuiltIn: "Administrator", Disabled: model.Yes}, {Name: "sam", Disabled: model.No}},
			HostsPath: `C:\Windows\System32\drivers\etc\hosts`, HostsVisible: true,
			Hosts: []model.HostsEntry{{Address: "127.0.0.1", Names: []string{"localhost"}}},
		},
	}
}

func build(s *model.Snapshot) *Book { return Build(s, rules.Check(s)) }

// cells joins the cells of a row, to look for it by what it shows.
func find(t *testing.T, page Page, needle string) Row {
	t.Helper()
	for _, row := range page.Rows {
		if strings.Contains(strings.Join(row.Cells, " | "), needle) {
			return row
		}
	}
	t.Fatalf("the %s page has no row with %q", page.Name, needle)
	return Row{}
}

func words(lines []Line) string {
	var all []string
	for _, line := range lines {
		all = append(all, line.Text)
	}
	return strings.Join(all, "\n")
}

func TestHealthyPC(t *testing.T) {
	book := build(pc())
	if len(book.Findings) != 0 {
		t.Fatalf("the made-up healthy PC has findings: %+v", book.Findings)
	}
	if want := "STUDY-PC, Windows 10 Pro 22H2. Looked at on 22 November 2026 at 14:02 as sam, without administrator rights, so some details could not be read."; book.Summary != want {
		t.Errorf("summary:\n   got %s\n  want %s", book.Summary, want)
	}
	for _, page := range book.Pages() {
		if page.Name == "" || page.Title == "" || page.Intro == "" || len(page.Columns) < 3 {
			t.Errorf("the page %q lacks a name, a title, an introduction or columns", page.Name)
		}
		if page.Name != "Worth a look" && len(page.Rows) == 0 {
			t.Errorf("the %s page is empty", page.Name)
		}
		if page.Count() != 0 {
			t.Errorf("the %s page of a healthy PC has %d rows worth a look", page.Name, page.Count())
		}
		for _, row := range page.Rows {
			if len(row.Cells) != len(page.Columns) {
				t.Errorf("%s: a row has %d cells for %d columns: %q", page.Name, len(row.Cells), len(page.Columns), row.Cells)
			}
			if len(row.Detail) < 2 || row.Detail[0].Style != Heading {
				t.Errorf("%s: the row %q has no detail under a heading", page.Name, row.Cells)
			}
			for _, line := range row.Detail {
				if strings.TrimSpace(line.Text) == "" {
					t.Errorf("%s: the row %q has an empty line of detail", page.Name, row.Cells)
				}
			}
		}
	}
	for _, glance := range book.Glances {
		if glance.Light != rules.Green || glance.Verdict != "Nothing stands out" || glance.Facts == "" {
			t.Errorf("%s: %v, %q, %q", glance.Area, glance.Light, glance.Verdict, glance.Facts)
		}
	}
	if got := book.Glances[model.Protection].Facts; got != "Antivirus on. Firewall on. Last update 9 days ago." {
		t.Errorf("protection in a line: %q", got)
	}
	if got := book.Glances[model.StartsWithWindows].Facts; got != "3 things are set to start by themselves. 1 is not part of Windows." {
		t.Errorf("start-up in a line: %q", got)
	}
	if got := book.Glances[model.Accounts].Facts; got != "1 administrator account in use. Remote Desktop off. No remote-control software found." {
		t.Errorf("accounts in a line: %q", got)
	}
}

func TestRowsOfAHealthyPC(t *testing.T) {
	book := build(pc())
	// A service shows its friendly name, and the library that does its work.
	audio := find(t, book.Startup, "Windows Audio")
	if audio.Cells[2] != "Service" || audio.Cells[3] != "Microsoft Windows" || audio.Cells[4] != `C:\Windows\System32\audiosrv.dll` || !audio.Windows || audio.Path == "" {
		t.Errorf("the audio service: %q, part of Windows %v", audio.Cells, audio.Windows)
	}
	for _, want := range []string{"A background program that Windows starts by itself", "Name in Windows: Audiosrv", "Runs as: LOCAL SERVICE", "Running now: Yes", "About: Manages audio.",
		`C:\Windows\System32\svchost.exe -k audio`, "Signature: Signed by Microsoft Windows", `Started through:`} {
		if !strings.Contains(words(audio.Detail), want) {
			t.Errorf("the audio service's detail lacks %q:\n%s", want, words(audio.Detail))
		}
	}
	if notes := find(t, book.Startup, "Notes"); notes.Windows || notes.Cells[0] != "" {
		t.Errorf("a program from another maker: %q, part of Windows %v", notes.Cells, notes.Windows)
	}
	// A Windows task that names no file is still Windows' own, and says so.
	task := find(t, book.Startup, `\Microsoft\Windows\Thing\Task`)
	if !task.Windows || task.Cells[3] != "No file named" || !strings.Contains(words(task.Detail), "could not work out which file") {
		t.Errorf("a task with no file: %q", task.Cells)
	}
	// The running programs are a family tree.
	var names []string
	for _, row := range book.Running.Rows {
		names = append(names, row.Cells[1])
	}
	if got := strings.Join(names, "|"); got != "explorer.exe|    notes.exe|System|    svchost.exe" {
		t.Errorf("the tree: %q", got)
	}
	notes := find(t, book.Running, "notes.exe")
	for _, want := range []string{"Started by: explorer.exe (number 3000)", "Running since: 22 November 2026, 14:01", `"C:\Program Files\Notes\notes.exe"`, "The file says it is: A program, by Notes Ltd"} {
		if !strings.Contains(words(notes.Detail), want) {
			t.Errorf("the detail of notes.exe lacks %q:\n%s", want, words(notes.Detail))
		}
	}
	host := find(t, book.Running, "svchost.exe")
	if !strings.Contains(words(host.Detail), "can only be read with administrator rights") || !strings.Contains(words(host.Detail), "Services inside it: Audiosrv") {
		t.Errorf("a service host's detail:\n%s", words(host.Detail))
	}
	if system := find(t, book.Running, "System"); system.Cells[4] != "Part of Windows itself" || !system.Windows {
		t.Errorf("the System process: %q", system.Cells)
	}
	// Connections say where the other end is and what the port is for.
	out := find(t, book.Connections, "93.184.216.34:443")
	if out.Cells[2] != "Connected to" || out.Cells[4] != "Internet" || !strings.Contains(words(out.Detail), "normally used for web (HTTPS)") {
		t.Errorf("a connection to the internet: %q\n%s", out.Cells, words(out.Detail))
	}
	share := find(t, book.Connections, "TCP port 445")
	if share.Cells[2] != "Waits for connections" || share.Cells[4] != "The network" || share.Cells[5] != "Part of Windows itself" {
		t.Errorf("a port open to the network: %q", share.Cells)
	}
	if local := find(t, book.Connections, "UDP port 5000"); local.Cells[2] != "Open to receive" || local.Cells[4] != "This PC only" {
		t.Errorf("a port open to this PC only: %q", local.Cells)
	}
	// Protection and accounts read as settled facts.
	for needle, want := range map[string]string{
		"Antivirus":            "OK | Antivirus | Microsoft Defender Antivirus: on, up to date",
		"Firewall":             "OK | Firewall | Windows Firewall is on for private networks and public networks",
		"User Account Control": "OK | User Account Control | On, and asks before giving a program full rights",
		"Windows updates":      "OK | Windows updates | Last update installed on 13 November 2026, 9 days ago",
		"Places Defender":      "OK | Places Defender skips | None",
		"Disk C:":              "OK | Disk C: encryption | On",
		"Hosts file":           "OK | Hosts file | No entries",
	} {
		if got := strings.Join(find(t, book.Protection, needle).Cells, " | "); got != want {
			t.Errorf("protection row:\n   got %s\n  want %s", got, want)
		}
	}
	for needle, want := range map[string]string{
		"sam":            "OK | Administrator account | sam, in use",
		"built-in":       "OK | Administrator account | Administrator, switched off (the built-in Administrator account every PC has)",
		"Guest":          "OK | Guest account | Off",
		"Remote Desktop": "OK | Remote Desktop | Off",
		"Remote-control": "OK | Remote-control software | None of the programs LazaScope knows by name was found",
	} {
		if got := strings.Join(find(t, book.Accounts, needle).Cells, " | "); got != want {
			t.Errorf("accounts row:\n   got %s\n  want %s", got, want)
		}
	}
}

func TestFlaggedRows(t *testing.T) {
	s := pc()
	fake := signed(`C:\Users\sam\Downloads\svchost.exe`, "Microsoft Windows")
	tool := unsigned(`C:\Program Files\Tool\tool.exe`)
	old := entry(model.RunKey, "Old", unsigned(`C:\Program Files\Old\old.exe`))
	old.Enabled = false
	s.Startup = append(s.Startup, old, entry(model.RunKey, "Tool", tool))
	s.Processes = append(s.Processes,
		model.Process{PID: 9000, Parent: 3000, Name: "svchost.exe", File: fake, User: "sam", Command: `C:\Users\sam\Downloads\svchost.exe`},
		model.Process{PID: 9001, Parent: 9000, Name: "svchost.exe", File: fake, User: "sam", Command: `C:\Users\sam\Downloads\svchost.exe --child`},
		model.Process{PID: 9100, Parent: 3000, Name: "AnyDesk.exe", File: signed(`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`, "AnyDesk Software GmbH"), User: "sam"})
	s.Connections = append(s.Connections, model.Connection{Protocol: "TCP", Listening: true, State: "Waiting for connections", Local: "0.0.0.0", LocalPort: 8080, Reach: model.LocalNetwork, PID: 9200, Process: "tool.exe", File: tool})
	s.Guard.UACSilent = model.Yes
	s.Guard.SecureBoot = model.No
	s.Gaps = []model.Gap{{Area: model.Protection, What: "The exclusions could not be read."}, {Area: model.RunningNow, What: "Some commands could not be read."}}
	book := build(s)

	// The flagged entry leads its list, and its detail carries the reason and the advice.
	first := book.Startup.Rows[0]
	if first.Cells[0] != "Worth a look" || first.Cells[1] != "Tool" || first.Level != Look {
		t.Fatalf("the first start-up row is %q", first.Cells)
	}
	for _, want := range []string{"Worth a look: Starts by itself and is not signed by its maker", "carries no maker's signature", "What you can do: ", "Signature: Not signed"} {
		if !strings.Contains(words(first.Detail), want) {
			t.Errorf("the flagged entry's detail lacks %q:\n%s", want, words(first.Detail))
		}
	}
	// An entry that is switched off says so and is not flagged.
	if off := find(t, book.Startup, "Old"); off.Cells[0] != "Off" || !off.Off || off.Level != Plain || !strings.Contains(words(off.Detail), "switched off") {
		t.Errorf("an entry that is switched off: %q", off.Cells)
	}
	if book.Startup.Count() != 1 {
		t.Errorf("%d start-up rows are worth a look, want 1", book.Startup.Count())
	}
	// Every running copy of the disguised program is marked, where it stands in the tree.
	marked := 0
	for _, row := range book.Running.Rows {
		if strings.TrimSpace(row.Cells[1]) == "svchost.exe" && row.Level == First {
			marked++
			if !strings.Contains(words(row.Detail), "Look first: A running program is named like a part of Windows") {
				t.Errorf("a disguised program's detail lacks the reason:\n%s", words(row.Detail))
			}
		}
	}
	if marked != 2 {
		t.Errorf("%d copies of the disguised program are marked, want 2", marked)
	}
	for _, row := range book.Running.Rows {
		if row.Cells[2] == "900" && row.Level != Plain {
			t.Errorf("the real svchost.exe is marked %v", row.Level)
		}
	}
	// The unsigned program's waiting port is marked.
	if port := find(t, book.Connections, "TCP port 8080"); port.Level != Look || book.Connections.Rows[0].Cells[3] != "TCP port 8080" {
		t.Errorf("the unsigned program's port: level %v, first row %q", port.Level, book.Connections.Rows[0].Cells)
	}
	// Settings carry what the rules said.
	uac := find(t, book.Protection, "User Account Control")
	if uac.Level != Look || uac.Cells[2] != "On, but set never to ask" || !strings.Contains(words(uac.Detail), "never notify") {
		t.Errorf("User Account Control: %q\n%s", uac.Cells, words(uac.Detail))
	}
	if boot := find(t, book.Protection, "Secure Boot"); boot.Level != Info || boot.Cells[0] != "Good to know" {
		t.Errorf("Secure Boot: %q", boot.Cells)
	}
	if desk := find(t, book.Accounts, "AnyDesk"); desk.Level != Look || desk.Cells[2] != "AnyDesk: running now" {
		t.Errorf("AnyDesk: %q", desk.Cells)
	}
	// The list of findings is the rules' own, the most serious first.
	if len(book.Worth.Rows) != len(book.Findings) || len(book.Findings) != 7 {
		t.Fatalf("%d rows for %d findings, want 7 of each", len(book.Worth.Rows), len(book.Findings))
	}
	top := book.Worth.Rows[0]
	if top.Cells[0] != "Look first" || top.Cells[1] != "Running now" || top.Path != fake.Path {
		t.Errorf("the first finding: %q, file %q", top.Cells, top.Path)
	}
	for _, want := range []string{"What you can do", "The facts", "File:", fake.Path, "Rule: running-system-name"} {
		if !strings.Contains(words(top.Detail), want) {
			t.Errorf("the first finding's detail lacks %q:\n%s", want, words(top.Detail))
		}
	}
	// The lights and their words.
	for area, want := range map[model.Area]string{
		model.Protection:        "1 worth a look, 1 good to know",
		model.StartsWithWindows: "1 worth a look",
		model.RunningNow:        "1 to look at first, 1 worth a look", // the disguise, and that it runs from Downloads
		model.Connections:       "1 worth a look",
		model.Accounts:          "1 worth a look",
	} {
		if got := book.Glances[area].Verdict; got != want {
			t.Errorf("%s: %q, want %q", area, got, want)
		}
	}
	if book.Glances[model.RunningNow].Light != rules.Red || book.Glances[model.Protection].Light != rules.Amber {
		t.Errorf("lights: %v and %v", book.Glances[model.RunningNow].Light, book.Glances[model.Protection].Light)
	}
	// What could not be read is said on the page it belongs to, and all of it on the last page.
	if len(book.Protection.Unseen) != 1 || len(book.Running.Unseen) != 1 || len(book.Startup.Unseen) != 0 || len(book.Worth.Unseen) != 2 {
		t.Errorf("unseen: %d, %d, %d, %d", len(book.Protection.Unseen), len(book.Running.Unseen), len(book.Startup.Unseen), len(book.Worth.Unseen))
	}
}

func TestWhatCouldNotBeRead(t *testing.T) {
	// A look that got nothing back must not read as a clean bill of health.
	book := build(&model.Snapshot{Taken: taken, Computer: "PC"})
	for _, glance := range book.Glances {
		if glance.Light != rules.Grey || glance.Verdict != "Could not be read" {
			t.Errorf("%s: %v, %q", glance.Area, glance.Light, glance.Verdict)
		}
	}
	for needle, page := range map[string]Page{"Antivirus": book.Protection, "Firewall": book.Protection, "Windows updates": book.Protection, "Remote Desktop": book.Accounts, "Guest": book.Accounts} {
		if row := find(t, page, needle); row.Level != Unknown || row.Cells[0] != "Not known" {
			t.Errorf("%s with nothing read: %q", needle, row.Cells)
		}
	}
	if row := find(t, book.Accounts, "Administrator accounts"); row.Cells[2] != "Could not be read" {
		t.Errorf("administrators with nothing read: %q", row.Cells)
	}
	// With administrator rights the summary says so.
	s := pc()
	s.Elevated = true
	if got := build(s).Summary; !strings.HasSuffix(got, "as sam, with administrator rights.") {
		t.Errorf("summary: %s", got)
	}
}

func TestSmallWords(t *testing.T) {
	for days, want := range map[int]string{0: "today", 1: "yesterday", 9: "9 days ago", -1: "today"} {
		if got := ago(days); got != want {
			t.Errorf("ago(%d) = %q, want %q", days, got, want)
		}
	}
	for level, want := range map[Level]string{Plain: "", Fine: "OK", Info: "Good to know", Look: "Worth a look", First: "Look first", Unknown: "Not known"} {
		if got := level.String(); got != want {
			t.Errorf("level %d = %q, want %q", level, got, want)
		}
	}
	if count(1, "thing", "things") != "1 thing" || count(2, "thing", "things") != "2 things" {
		t.Error("count words wrongly")
	}
}

// The overview's count of what is not part of Windows is the count of rows
// the list shows under the view of that name. Entries that are switched
// off and entries that name no file are counted the same way in both.
func TestOverviewAgreesWithTheList(t *testing.T) {
	s := pc()
	off := entry(model.RunKey, "Old", unsigned(`C:\Program Files\Old\old.exe`))
	off.Enabled = false
	s.Startup = append(s.Startup, off,
		model.Startup{Kind: model.StoreApp, Name: "Music", Where: "a made-up place", Enabled: true, Untraced: true},              // names no file, and is not Windows' own
		model.Startup{Kind: model.ScheduledTask, Name: `\Updater\Check`, Where: "Task Scheduler", Enabled: true, Untraced: true}) // the same, for a task of another maker
	book := build(s)
	other := 0
	for _, row := range book.Startup.Rows {
		if !row.Windows {
			other++
		}
	}
	if other != 4 {
		t.Fatalf("%d rows are not part of Windows, want 4 (Notes, Old, Music and the updater's task)", other)
	}
	if got, want := book.Glances[model.StartsWithWindows].Facts, "6 things are set to start by themselves, 1 of them switched off. 4 are not part of Windows."; got != want {
		t.Errorf("start-up in a line:\n   got %s\n  want %s", got, want)
	}
	// One entry alone reads as one.
	s = pc()
	s.Startup = s.Startup[:1]
	if got, want := build(s).Glances[model.StartsWithWindows].Facts, "1 thing is set to start by itself. 1 is not part of Windows."; got != want {
		t.Errorf("a single entry in a line:\n   got %s\n  want %s", got, want)
	}
	// The same holds for the running programs.
	book = build(pc())
	other = 0
	for _, row := range book.Running.Rows {
		if !row.Windows {
			other++
		}
	}
	if got, want := book.Glances[model.RunningNow].Facts, "4 programs are running. 1 of them is not part of Windows."; got != want || other != 1 {
		t.Errorf("running in a line: %q, and %d rows are not part of Windows", got, other)
	}
}

// A script is not a program, and the lists say which of the two a file is.
func TestScriptsAndDocuments(t *testing.T) {
	const folder = `C:\Users\sam\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
	s := pc()
	s.Startup = append(s.Startup,
		entry(model.StartupFolder, "open.cmd", model.File{Path: folder + `\open.cmd`, Exists: true}),
		entry(model.StartupFolder, "todo.txt", model.File{Path: folder + `\todo.txt`, Exists: true}))
	book := build(s)
	script := find(t, book.Startup, "open.cmd")
	if script.Level != Look || script.Cells[0] != "Worth a look" || script.Cells[3] != "Script file" || script.Windows {
		t.Errorf("a batch file in the Startup folder: %q, level %v", script.Cells, script.Level)
	}
	for _, want := range []string{"Worth a look: Starts a script by itself", "This is a script: a text file of commands, not a program.", "open Notepad, then drag the file into its window"} {
		if !strings.Contains(words(script.Detail), want) {
			t.Errorf("the batch file's detail lacks %q:\n%s", want, words(script.Detail))
		}
	}
	document := find(t, book.Startup, "todo.txt")
	if document.Level != Plain || document.Cells[0] != "" || document.Cells[3] != "Not a program file" {
		t.Errorf("a text file in the Startup folder: %q, level %v", document.Cells, document.Level)
	}
	if !strings.Contains(words(document.Detail), "This is not a program file, so there is no maker's signature to check.") {
		t.Errorf("the text file's detail:\n%s", words(document.Detail))
	}
	if len(book.Findings) != 1 || book.Findings[0].Rule != "startup-script" {
		t.Errorf("findings: %+v", book.Findings)
	}
}

// Which files count as parts of Windows decides what the lists show first.
func TestPartOfWindows(t *testing.T) {
	folders := pc().Folders
	for _, test := range []struct {
		file model.File
		want bool
	}{
		{signed(`C:\Windows\System32\svchost.exe`, "Microsoft Windows"), true},
		{signed(`C:\Windows\System32\smss.exe`, "Microsoft Windows Publisher"), true},
		{signed(`C:\Windows\System32\compattelrunner.exe`, "Microsoft Corporation"), true}, // signed twice; the checker reports this name
		{signed(`C:\Windows\System32\drivers\intelpep.sys`, "Microsoft Windows Hardware Abstraction Layer Publisher"), true},
		// Another maker's driver that Microsoft approved is not a part of Windows.
		{signed(`C:\Windows\System32\drivers\gfx.sys`, "Microsoft Windows Hardware Compatibility Publisher"), false},
		{signed(`C:\Windows\System32\DriverStore\FileRepository\audio.inf_amd64_1\AudioService.exe`, "Northwind Audio Ltd"), false},
		// A Microsoft product outside the Windows folder is an installed program like any other.
		{signed(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, "Microsoft Corporation"), false},
		// The right name in the wrong place, or with no signature, counts for nothing.
		{signed(`C:\Users\sam\Downloads\svchost.exe`, "Microsoft Windows"), false},
		{signed(`C:\Windows\Temp\svchost.exe`, "Microsoft Windows"), false},
		{unsigned(`C:\Windows\System32\thing.exe`), false},
		{model.File{}, false},
	} {
		if got := partOfWindows(test.file, folders); got != test.want {
			t.Errorf("%s signed by %q: got %v, want %v", test.file.Path, test.file.Signature.Signer, got, test.want)
		}
	}
}
