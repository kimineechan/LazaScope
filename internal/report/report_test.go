package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/sigcheck"
	"lazascope/internal/view"
)

// opened finds a box of the web page that starts open.
var opened = regexp.MustCompile(`<details[^>]*\sopen[\s>=]`)

func book(change func(s *model.Snapshot)) *view.Book {
	s := sample.PC()
	if change != nil {
		change(s)
	}
	return view.Build(s, rules.Check(s))
}

func TestHTML(t *testing.T) {
	b := book(nil)
	page := string(HTML(b, "1.0.0"))
	things := len(items(b.Findings))
	for _, want := range []string{
		"<!doctype html>", "<title>LazaScope report: STUDY-PC, ", "<h1>LazaScope</h1>", "What starts. What runs. What is worth a second look.",
		"<h2>This PC at a glance</h2>", "STUDY-PC, Windows 11 Home 24H2. Looked at on ", "Read it before you send it to anyone.",
		"<h2>What is worth a second look (25)</h2>", "25 findings about " + strconv.Itoa(things) + " things.</p>",
		"<h2>What could not be read</h2>", "<h2>Everything LazaScope read</h2>",
		"Named like a part of Windows, but not where Windows keeps it", "Starts a scripting tool with a scrambled command", `<span class="label">What you can do:</span>`,
		"Rule: startup-system-name. MITRE ATT&amp;CK", "How this PC is protected", "Who can get into this PC", "What starts by itself", "What is running now", "What is talking to the network",
		"LazaScope is not an antivirus", "Made by LazaScope 1.0.0 on ", "This page holds no scripts and loads nothing from the internet.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the web page lacks %q", want)
		}
	}
	for _, glance := range b.Glances {
		if !strings.Contains(page, "<b>"+glance.Area.String()+"</b>") {
			t.Errorf("the web page lacks the light for %s", glance.Area)
		}
	}
	// It wears the colours of the window, dark, and turns light only on paper.
	for _, colour := range []string{"color-scheme:dark", "--sheet:#121212", "--ink:#f3f3f3", "--good:#5fcb80", "--warn:#f2b33d", "--bad:#ff5449", "@media print"} {
		if !strings.Contains(page, colour) {
			t.Errorf("the web page's style lacks %q", colour)
		}
	}
	// The lists follow the window's section buttons, numbered as there, and
	// start closed so that the page is short until a list is opened.
	last := 0
	for i, name := range []string{"Protection", "Start-up", "Running", "Connections", "Accounts", "Health"} {
		at := strings.Index(page, fmt.Sprintf(`<span class="num">%02d</span><b>%s</b>`, i+2, name))
		if at < last {
			t.Errorf("the list %02d %s is missing or out of order", i+2, name)
		}
		last = at
	}
	if opened.MatchString(page) {
		t.Error("something in the web page starts open")
	}
	// One item flagged three times is shown once: its facts once, and the way
	// to switch it off once.
	host := strings.Index(page, "<h3>Windows Host Service<")
	if host < 0 {
		t.Fatal("the web page lacks the item Windows Host Service")
	}
	block := page[host : host+strings.Index(page[host:], "</article>")]
	if strings.Count(block, `<div class="finding">`) != 3 || strings.Count(block, "<dt>Command</dt>") != 1 || strings.Count(block, "To stop it starting, open Task Manager") != 1 || !strings.Contains(block, `<span class="where">03 Start-up</span>`) {
		t.Errorf("the item Windows Host Service: %s", block)
	}
	// The page must be whole in itself: nothing run, nothing fetched.
	for _, never := range []string{"<script", "<link", "<img", "<iframe", "src=", "href=", "url(", "@import", "http://", "https://", "onclick", "onload"} {
		if strings.Contains(strings.ToLower(page), never) {
			t.Errorf("the web page contains %q, so it is not whole in itself", never)
		}
	}
	// Every row of every list is there, and what is opened is closed.
	rows := len(b.Protection.Rows) + len(b.Accounts.Rows) + len(b.Health.Rows) + len(b.Startup.Rows) + len(b.Running.Rows) + len(b.Connections.Rows)
	if got := strings.Count(page, "<details>"); got != rows {
		t.Errorf("%d rows in the web page, want %d", got, rows)
	}
	for _, tag := range []string{"details", "summary", "div", "ul", "li", "dl", "main", "header", "footer", "article", "h1", "h2", "h3", "h4", "p", "b", "code", "span"} {
		if open, shut := strings.Count(page, "<"+tag+">")+strings.Count(page, "<"+tag+" "), strings.Count(page, "</"+tag+">"); open != shut {
			t.Errorf("<%s> is opened %d times and closed %d times", tag, open, shut)
		}
	}
	if strings.Count(page, `class="finding`) != len(b.Findings) {
		t.Errorf("%d findings in the web page, want %d", strings.Count(page, `class="finding`), len(b.Findings))
	}
	// A look held against a report says what changed, and that too is closed.
	compared := string(HTML(book(func(s *model.Snapshot) {
		s.Compared = &model.Comparison{With: "earlier.json", When: s.Taken.Add(-time.Hour), Gone: []string{"Old Tool, which started by itself"}}
	}), "1.0.0"))
	if !strings.Contains(compared, `<details class="more"><summary>What has changed or gone</summary>`) || opened.MatchString(compared) {
		t.Error("the changes of a comparison are not in a closed box of their own")
	}
}

// Findings about the same thing are gathered, in the order of the most
// serious finding about each, and none is lost.
func TestItems(t *testing.T) {
	b := book(nil)
	all := items(b.Findings)
	n := 0
	for i, it := range all {
		n += len(it.findings)
		for _, f := range it.findings {
			if f.Ref != it.findings[0].Ref {
				t.Errorf("item %d mixes %s and %s", i, f.Ref, it.findings[0].Ref)
			}
		}
		if i > 0 && it.findings[0].Severity > all[i-1].findings[0].Severity {
			t.Errorf("item %d (%s) is more serious than the one before it", i, it.subject)
		}
	}
	if n != len(b.Findings) || len(all) >= len(b.Findings) {
		t.Errorf("%d items hold %d findings, of %d", len(all), n, len(b.Findings))
	}
	for _, it := range all {
		if it.subject == "Windows Host Service" {
			if len(it.findings) != 3 || it.findings[0].Severity != rules.High {
				t.Errorf("Windows Host Service: %+v", it.findings)
			}
			seen := map[string]bool{}
			for _, fact := range it.evidence(b.Snapshot) {
				key := fact.Label + "=" + fact.Value
				if seen[key] {
					t.Errorf("the fact %s is given twice", key)
				}
				seen[key] = true
			}
			if !seen["Fingerprint of that file (SHA-256)=a952348c8cf60593a91c438276fc4a50315c1f8fe8249bdc08e53a9dd24b18f1"] || !seen["VirusTotal's label=trojan.fakesvc/example"] {
				t.Errorf("the facts of Windows Host Service lack its fingerprint or what VirusTotal said: %v", seen)
			}
		}
	}
}

// Advice that an earlier finding about the same thing already gave is not
// given again, but a sentence that leans on the one before it keeps it.
func TestFresh(t *testing.T) {
	given := map[string]bool{}
	for _, c := range []struct{ advice, want string }{
		{"Scan it. To stop it starting, switch it off. That does not delete anything.", "Scan it. To stop it starting, switch it off. That does not delete anything."},
		{"Do not open it. Choose Look up file... to read more. To stop it starting, switch it off. That does not delete anything.", "Do not open it. Choose Look up file... to read more."},
		{"To stop it starting, switch it off. That keeps it from starting at sign-in.", "To stop it starting, switch it off. That keeps it from starting at sign-in."},
		{"Scan it.", ""},
		{"", ""},
	} {
		if got := fresh(c.advice, given); got != c.want {
			t.Errorf("fresh(%q) = %q, want %q", c.advice, got, c.want)
		}
	}
	if got := sentences("Open Windows 11 build 26100.2314 first. Then C:\\Windows\\MEMORY.DMP. Done!"); len(got) != 3 {
		t.Errorf("sentences: %q", got)
	}
}

// Whatever a program calls itself goes into the report as text. A name
// written to look like part of a web page must stay text.
// A saved report is made to be sent, so the lines LazaScope copies out of
// a script stay out of it. What the script does is still said.
func TestReportLeavesScriptLinesOut(t *testing.T) {
	b := book(nil)
	const secret = "Opens what I need for studying"
	shown := false
	for _, row := range b.Startup.Rows {
		for _, line := range row.Detail {
			shown = shown || strings.Contains(line.Text, secret)
		}
	}
	if !shown {
		t.Fatal("the window would not show the script's lines, so this test proves nothing")
	}
	page := string(HTML(b, "1.0.0"))
	if strings.Contains(page, secret) || strings.Contains(page, "library.example.ac.uk") {
		t.Error("the web page holds lines copied out of a script")
	}
	if strings.Count(page, "They are left out of this report, in case they hold a password.") != 2 {
		t.Error("the web page does not say, once for the script and once for the decoded command, that the lines were left out")
	}
	if strings.Contains(page, "DownloadString") || strings.Contains(Text(b, "1.0.0"), "DownloadString") {
		t.Error("a report holds lines of a decoded command")
	}
	if !strings.Contains(page, "It deletes files or folders.") {
		t.Error("the web page does not say what the script does")
	}
	for name, content := range map[string][]byte{"text": []byte(Text(b, "1.0.0")), "data": JSON(b, "1.0.0")} {
		if strings.Contains(string(content), secret) {
			t.Errorf("the %s report holds lines copied out of a script", name)
		}
	}
	if !strings.Contains(string(JSON(b, "1.0.0")), "\"scriptDoes\": [") {
		t.Error("the data does not say what the script does")
	}
}

func TestHTMLKeepsNamesAsText(t *testing.T) {
	const nasty = `<script>alert("x")</script><img src=x onerror=alert(1)>&"'`
	b := book(func(s *model.Snapshot) {
		file := model.File{Path: `C:\Users\sam\Downloads\` + nasty + `.exe`, Exists: true, Program: true, Company: nasty, Description: nasty, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}
		s.Startup = append(s.Startup, model.Startup{Kind: model.RunKey, Name: nasty, Where: nasty, Command: nasty, Program: file, Target: file, Enabled: true, Description: nasty, Account: nasty, Trigger: nasty})
		s.Processes = append(s.Processes, model.Process{PID: 9999, Name: nasty, File: file, User: nasty, Command: nasty})
		s.Connections = append(s.Connections, model.Connection{Protocol: "TCP", Listening: true, Local: "0.0.0.0", LocalPort: 81, Reach: model.LocalNetwork, PID: 9999, Process: nasty, File: file, Services: []string{nasty}})
		s.Guard.Hosts = append(s.Guard.Hosts, model.HostsEntry{Address: nasty, Names: []string{nasty}})
		s.Guard.Admins = append(s.Guard.Admins, model.Account{Name: nasty})
		s.Guard.Exclusions, s.Guard.ExclusionsVisible = []model.Exclusion{{Kind: "Folder or file", Value: nasty}}, true
		s.Computer, s.User, s.Windows = nasty, nasty, nasty
		s.Gaps = append(s.Gaps, model.Gap{Area: model.Protection, What: nasty})
	})
	page := string(HTML(b, nasty))
	if strings.Contains(page, "<script") || strings.Contains(page, "<img") || strings.Contains(page, `onerror=alert(1)>`) {
		t.Error("a name got into the web page as markup")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Error("the name is not in the web page as text")
	}
}

func TestText(t *testing.T) {
	b := book(nil)
	text := Text(b, "1.0.0")
	for _, want := range []string{
		"LazaScope report\r\n", "Made by LazaScope 1.0.0 on ", "AT A GLANCE\r\n", "WORTH A LOOK (25)\r\n", "25 findings about ",
		"Windows Host Service, under 03 Start-up\r\n", "  [Look first] Named like a part of Windows, but not where Windows keeps it\r\n",
		"      Why: ", "      What you can do: ", "  Details:\r\n", "      Rule: startup-system-name. MITRE ATT&CK 20.1: T1036.005", "      Rule: startup-virustotal-flags\r\n",
		"WHAT COULD NOT BE READ\r\n", "Check | Name | Kind | Maker | VirusTotal | File\r\n",
		"Look first | Windows Host Service | Registry Run | Not signed | 25 of 72 | C:\\Users\\sam\\AppData\\Roaming\\svchost.exe\r\n", "LazaScope is not an antivirus",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text report lacks %q", want)
		}
	}
	// The lists come in the order of the window's section buttons.
	last := 0
	for _, heading := range []string{"02 PROTECTION: HOW THIS PC IS PROTECTED (13)", "03 START-UP: WHAT STARTS BY ITSELF (", "04 RUNNING: WHAT IS RUNNING NOW (", "05 CONNECTIONS: WHAT IS TALKING TO THE NETWORK (", "06 ACCOUNTS: WHO CAN GET INTO THIS PC (", "07 HEALTH: HOW THIS PC IS HOLDING UP ("} {
		at := strings.Index(text, heading)
		if at < last {
			t.Errorf("the list %q is missing or out of order", heading)
		}
		last = at
	}
	// An item flagged three times gives its facts once, but two hardware
	// errors in the same minute stay two.
	if n := strings.Count(text, "      Command: C:\\Users\\sam\\AppData\\Roaming\\svchost.exe\r\n"); n != 1 {
		t.Errorf("the command of Windows Host Service is given %d times", n)
	}
	if n := strings.Count(text, ": A corrected hardware error has occurred."); n != len(b.Snapshot.Condition.Hardware) || n != 4 {
		t.Errorf("%d hardware errors in the text report, want the 4 the made-up PC has", n)
	}
	// Dates are written the same way throughout, as words.
	for _, number := range []string{"Last update installed: 2026-", "Running since: 2026-", "is not encrypted (off)"} {
		if strings.Contains(text, number) {
			t.Errorf("the text report says %q", number)
		}
	}
	if strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\n") {
		t.Error("a line of the text report does not end the way Notepad expects")
	}
	// A cell with nothing in it is written as a dash, so that no line ends
	// in a bar and a space as if something had been cut off.
	untraced := Text(book(func(s *model.Snapshot) {
		s.Startup = append(s.Startup, model.Startup{Kind: model.ScheduledTask, Name: `\Microsoft\Windows\Thing\Task`, Where: "Task Scheduler", Enabled: true, Untraced: true})
	}), "1.0.0")
	if want := "- | \\Microsoft\\Windows\\Thing\\Task | Scheduled task | No file named | - | -\r\n"; !strings.Contains(untraced, want) {
		t.Errorf("the text report lacks %q", want)
	}
	for _, line := range strings.Split(untraced, "\r\n") {
		if strings.HasSuffix(line, " ") || strings.HasSuffix(line, "|") {
			t.Errorf("a line of the text report ends in a space or a bar: %q", line)
		}
	}
	if clean := Text(book(func(s *model.Snapshot) { *s = model.Snapshot{Taken: s.Taken, Computer: "PC"} }), "1.0.0"); !strings.Contains(clean, "Nothing on this PC stood out to the rules.") {
		t.Error("a report with no findings does not say so")
	}
}

func TestJSON(t *testing.T) {
	b := book(nil)
	type file struct {
		Path, Signature, SignedBy, SignatureIn, SaysCompany string
		Exists, Program                                     bool
	}
	var document struct {
		Tool, Generated, Computer, User, Windows, Summary string
		TookMilliseconds                                  int64
		AdministratorRights                               bool
		Lights                                            []struct{ Area, Light, Verdict, Facts string }
		Findings                                          []struct {
			Rule, Severity, Area, Title, Subject, Reason, Advice, Ref string
			Evidence                                                  map[string]string
		}
		CouldNotRead []string
		Facts        struct {
			Startup []struct {
				Ref, Kind, Name, RecordedIn, Command, StartedThrough, Trigger string
				Enabled                                                       bool
				File                                                          *file
			}
			Processes []struct {
				Ref, Name, Command, User, Started string
				PID, Parent                       uint32
				File                              *file
				Services                          []string
			}
			Connections []struct {
				Protocol, State, Local, Remote, Reach, Process, Path string
				LocalPort, RemotePort                                int
				Listening                                            bool
			}
			Protection struct {
				Antivirus                                           []struct{ Name, On, UpToDate string }
				AntivirusVerdict, UserAccountControl, RemoteDesktop string
				DefenderExclusionsReadable                          bool
				Volumes                                             []struct{ Drive, Encrypted, State string }
				Administrators                                      []struct{ Name, Disabled, BuiltIn string }
				HostsEntries                                        []struct {
					Address string
					Names   []string
				}
				InstalledPrograms []struct{ Name string }
				LastUpdate        string
			}
		}
	}
	data := JSON(b, "1.0.0")
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("the data is not valid JSON: %v", err)
	}
	if document.Tool != "LazaScope 1.0.0" || document.Computer != "STUDY-PC" || document.User != "sam" || len(document.Generated) != 20 || document.TookMilliseconds != 1900 || document.Summary != b.Summary {
		t.Errorf("the head of the data: %+v", document)
	}
	if len(document.Lights) != int(model.Areas) || document.Lights[1].Light != "red" || document.Lights[3].Light != "green" {
		t.Errorf("lights: %+v", document.Lights)
	}
	if len(document.Findings) != len(b.Findings) || len(document.CouldNotRead) != 3 {
		t.Fatalf("%d findings and %d notes", len(document.Findings), len(document.CouldNotRead))
	}
	// Every fact that was read is there, one record each.
	s, facts := b.Snapshot, document.Facts
	if len(facts.Startup) != len(s.Startup) || len(facts.Processes) != len(s.Processes) || len(facts.Connections) != len(s.Connections) {
		t.Fatalf("%d start-up entries, %d programs and %d connections in the data", len(facts.Startup), len(facts.Processes), len(facts.Connections))
	}
	// A finding points at the fact it is about.
	// The most serious come first, and among those the areas in their order:
	// what Defender's log shows, then the program with a borrowed name.
	if top := document.Findings[0]; top.Severity != "look first" || top.Rule != "defender-exclusions-logged" || top.Ref != "exclusions" {
		t.Fatalf("the first finding: %+v", top)
	}
	first := document.Findings[1]
	if first.Severity != "look first" || first.Rule != "startup-system-name" || first.Evidence["File"] == "" || !strings.HasPrefix(first.Ref, "startup:") {
		t.Fatalf("the first finding: %+v", first)
	}
	pointed := false
	for _, entry := range facts.Startup {
		if entry.Ref != first.Ref {
			continue
		}
		pointed = true
		if entry.Name != "Windows Host Service" || entry.Kind != "Registry Run" || !entry.Enabled || entry.File == nil ||
			entry.File.Path != `C:\Users\sam\AppData\Roaming\svchost.exe` || entry.File.Signature != "unsigned" || !entry.File.Program || !entry.File.Exists {
			t.Errorf("the entry the first finding points at: %+v, file %+v", entry, entry.File)
		}
	}
	if !pointed {
		t.Errorf("no start-up entry has the ref %s", first.Ref)
	}
	// A service shows the library that does its work, and the host that runs it.
	for _, entry := range facts.Startup {
		if entry.Name == "Audiosrv" {
			if entry.File == nil || entry.File.Path != `C:\Windows\System32\audiosrv.dll` || entry.StartedThrough != `C:\Windows\System32\svchost.exe` ||
				entry.File.Signature != "signed" || entry.File.SignedBy != "Microsoft Windows" || entry.File.SignatureIn != "catalogue" {
				t.Errorf("the audio service: %+v, file %+v", entry, entry.File)
			}
		}
	}
	for _, p := range facts.Processes {
		if p.Ref != "process:"+strconv.Itoa(int(p.PID)) || p.Name == "" {
			t.Errorf("a program without its ref or name: %+v", p)
		}
		if p.Name == "notes.exe" && (p.File == nil || p.File.SignedBy != "Brightline Software Ltd" || p.Parent != 3000 || p.User != "sam" || len(p.Started) != 20 || p.Command == "") {
			t.Errorf("notes.exe: %+v, file %+v", p, p.File)
		}
		if p.Name == "System" && p.File != nil {
			t.Errorf("the System process has a file: %+v", p.File)
		}
	}
	waiting := 0
	for _, c := range facts.Connections {
		if c.Listening {
			waiting++
			if c.Remote != "" || c.RemotePort != 0 {
				t.Errorf("a waiting port has another end: %+v", c)
			}
		} else if c.Remote == "" || c.RemotePort == 0 || c.Process == "" {
			t.Errorf("a connection without its other end or its program: %+v", c)
		}
	}
	if waiting != 8 {
		t.Errorf("%d waiting ports in the data, want 8", waiting)
	}
	p := facts.Protection
	if len(p.Antivirus) != 1 || p.Antivirus[0].On != "yes" || p.AntivirusVerdict != "yes" || p.UserAccountControl != "yes" || p.RemoteDesktop != "no" || p.DefenderExclusionsReadable ||
		len(p.Volumes) != 1 || p.Volumes[0].Encrypted != "no" || len(p.Administrators) != 2 || p.Administrators[0].Disabled != "yes" || len(p.HostsEntries) != 2 || len(p.InstalledPrograms) != 6 || len(p.LastUpdate) != 20 {
		t.Errorf("protection: %+v", p)
	}
	if !strings.HasSuffix(string(data), "}\n") {
		t.Error("the data does not end with a line break")
	}
	// Written as people type it: an apostrophe and a > as themselves, not as
	// escape codes (a backslash, a u and four digits).
	for _, code := range []string{"0027", "003e", "003c", "0026"} {
		if strings.Contains(string(data), "\\u"+code) {
			t.Errorf("the data writes the escape code for %s", code)
		}
	}
	if !strings.Contains(string(data), "Microsoft Defender's log") || !strings.Contains(string(data), "Virus and threat protection > Manage settings") {
		t.Error("the data lacks an apostrophe or a > written as itself")
	}
	// A look that read nothing still gives well-formed data, with empty lists and not nulls.
	empty := string(JSON(book(func(s *model.Snapshot) { *s = model.Snapshot{Taken: s.Taken, Computer: "PC"} }), "1.0.0"))
	for _, want := range []string{`"findings": []`, `"startup": []`, `"processes": []`, `"connections": []`, `"antivirus": []`, `"installedPrograms": []`, `"couldNotRead": []`} {
		if !strings.Contains(empty, want) {
			t.Errorf("the data of an empty look lacks %s", want)
		}
	}
	if strings.Contains(empty, "null") {
		t.Error("the data of an empty look holds a null")
	}
}

func TestColumns(t *testing.T) {
	if got := columns([]view.Column{{Title: "A", Width: 112}, {Title: "B", Width: 250}, {Title: "C"}}); got != "minmax(0,112fr) minmax(0,250fr) minmax(0,614fr)" {
		t.Errorf("got %q", got)
	}
	// A page whose columns already fill the width still gives its last one room.
	if got := columns([]view.Column{{Title: "A", Width: 900}, {Title: "B"}}); got != "minmax(0,900fr) minmax(0,120fr)" {
		t.Errorf("got %q", got)
	}
}

// The ending of the file name chooses the form, and an ending that is not a
// report's is refused before anything is written.
func TestRender(t *testing.T) {
	b := book(nil)
	for name, starts := range map[string]string{
		`C:\Users\sam\Desktop\report.html`: "<!doctype html>",
		`report.HTM`:                       "<!doctype html>",
		`report.txt`:                       "LazaScope report\r\n",
		`C:\out.put\report.JSON`:           "{",
	} {
		content, err := Render(b, "1.0.0", name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.HasPrefix(string(content), starts) {
			t.Errorf("%s starts with %q, want %q", name, string(content[:min(len(content), 40)]), starts)
		}
		if Fits(name) != nil {
			t.Errorf("%s is said not to fit", name)
		}
	}
	for _, name := range []string{"report", "report.pdf", "report.html.exe", `C:\folder.html\report`, ""} {
		content, err := Render(b, "1.0.0", name)
		if err == nil || content != nil {
			t.Errorf("%q was written as a report", name)
		} else if !strings.Contains(err.Error(), ".html, .txt or .json") {
			t.Errorf("%q: the refusal does not say what is taken: %v", name, err)
		}
		if Fits(name) == nil {
			t.Errorf("%q is said to fit", name)
		}
	}
}
