package report

import (
	"encoding/json"
	"strings"
	"testing"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/sigcheck"
	"lazascope/internal/view"
)

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
	for _, want := range []string{
		"<!doctype html>", "<title>LazaScope report: STUDY-PC, ", "STUDY-PC, Windows 11 Home 24H2. Looked at on ",
		"Read it before you send it to anyone.", "At a glance", "What is worth a second look", "What could not be read", "The facts",
		"Named like a part of Windows, but not where Windows keeps it", "Starts a scripting tool with a scrambled command", "<b>What you can do:</b>",
		"Rule: startup-system-name", "How this PC is protected", "Who can get into this PC", "What starts by itself", "What is running now", "What is talking to the network",
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
	// The page must be whole in itself: nothing run, nothing fetched.
	for _, never := range []string{"<script", "<link", "<img", "<iframe", "src=", "href=", "url(", "@import", "http://", "https://", "onclick", "onload"} {
		if strings.Contains(strings.ToLower(page), never) {
			t.Errorf("the web page contains %q, so it is not whole in itself", never)
		}
	}
	// Every row of every list is there, and what is opened is closed.
	rows := len(b.Protection.Rows) + len(b.Accounts.Rows) + len(b.Startup.Rows) + len(b.Running.Rows) + len(b.Connections.Rows)
	if got := strings.Count(page, "<details>"); got != rows {
		t.Errorf("%d rows in the web page, want %d", got, rows)
	}
	for _, tag := range []string{"details", "summary", "div", "ul", "dl", "main", "h2", "h3", "h4", "p", "code", "span"} {
		if open, shut := strings.Count(page, "<"+tag+">")+strings.Count(page, "<"+tag+" "), strings.Count(page, "</"+tag+">"); open != shut {
			t.Errorf("<%s> is opened %d times and closed %d times", tag, open, shut)
		}
	}
	if strings.Count(page, `class="finding`) != len(b.Findings) {
		t.Errorf("%d findings in the web page, want %d", strings.Count(page, `class="finding`), len(b.Findings))
	}
}

// Whatever a program calls itself goes into the report as text. A name
// written to look like part of a web page must stay text.
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
		"LazaScope report\r\n", "Made by LazaScope 1.0.0 on ", "AT A GLANCE\r\n", "WORTH A LOOK (10)\r\n", "[Look first] Named like a part of Windows, but not where Windows keeps it\r\n",
		"    Why: ", "    What you can do: ", "    Rule: startup-system-name\r\n", "WHAT COULD NOT BE READ\r\n", "WHAT STARTS BY ITSELF (", "Check | Name | Kind | Maker | File\r\n",
		"Look first | Windows Host Service | Registry Run | Not signed | C:\\Users\\sam\\AppData\\Roaming\\svchost.exe\r\n", "LazaScope is not an antivirus",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text report lacks %q", want)
		}
	}
	if strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\n") {
		t.Error("a line of the text report does not end the way Notepad expects")
	}
	if clean := Text(book(func(s *model.Snapshot) { *s = model.Snapshot{Taken: s.Taken, Computer: "PC"} }), "1.0.0"); !strings.Contains(clean, "Nothing on this PC stood out to the rules.") {
		t.Error("a report with no findings does not say so")
	}
}

func TestJSON(t *testing.T) {
	b := book(nil)
	var document struct {
		Tool, Generated, Computer, User, Windows string
		AdministratorRights                      bool
		Lights                                   []struct{ Area, Light, Verdict, Facts string }
		Findings                                 []struct {
			Rule, Severity, Area, Title, Subject, Reason, Advice string
			Facts                                                map[string]string
		}
		CouldNotRead []string
		Pages        map[string]struct {
			Title string
			Rows  []struct {
				Check  string
				Values map[string]string
				File   string
				Detail []string
			}
		}
	}
	data := JSON(b, "1.0.0")
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("the data is not valid JSON: %v", err)
	}
	if document.Tool != "LazaScope 1.0.0" || document.Computer != "STUDY-PC" || document.User != "sam" || len(document.Generated) != 20 {
		t.Errorf("the head of the data: %+v", document)
	}
	if len(document.Lights) != int(model.Areas) || document.Lights[1].Light != "red" || document.Lights[3].Light != "green" {
		t.Errorf("lights: %+v", document.Lights)
	}
	if len(document.Findings) != len(b.Findings) || document.Findings[0].Severity != "look first" || document.Findings[0].Facts["File"] == "" {
		t.Errorf("findings: %d, first %+v", len(document.Findings), document.Findings[0])
	}
	if len(document.CouldNotRead) != 2 || len(document.Pages) != 5 {
		t.Errorf("%d notes and %d pages", len(document.CouldNotRead), len(document.Pages))
	}
	startup := document.Pages["startup"]
	if len(startup.Rows) != len(b.Startup.Rows) || startup.Rows[0].Check != "Look first" || startup.Rows[0].Values["Name"] == "" || len(startup.Rows[0].Detail) == 0 {
		t.Errorf("the start-up page: %d rows, first %+v", len(startup.Rows), startup.Rows[0])
	}
	// The family tree's indenting is for the eye, not for data.
	for _, row := range document.Pages["running"].Rows {
		if strings.HasPrefix(row.Values["Program"], " ") {
			t.Errorf("a program's name starts with a space: %q", row.Values["Program"])
		}
	}
	if !strings.HasSuffix(string(data), "}\n") {
		t.Error("the data does not end with a line break")
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
