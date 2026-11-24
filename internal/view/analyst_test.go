package view

import (
	"strings"
	"testing"

	"lazascope/internal/query"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
)

// Every row carries what it is about, its evidence and its search values,
// and the evidence is exact.
func TestAnalystEvidence(t *testing.T) {
	s := sample.PC()
	b := Build(s, rules.Check(s))
	pages := append(b.Pages(), &b.VirusTotal)
	for _, page := range pages {
		for _, row := range page.Rows {
			if row.Ref == "" || len(row.Fields["page"]) != 1 || row.Text == "" {
				t.Errorf("%s: a row lacks its reference or search values: %v", page.Name, row.Cells)
			}
		}
	}
	var impostor *Row
	for i, row := range b.Startup.Rows {
		if row.Cells[1] == "Windows Host Service" {
			impostor = &b.Startup.Rows[i]
		}
	}
	if impostor == nil {
		t.Fatal("the impostor is not in the start-up list")
	}
	var raw []string
	for _, line := range impostor.Raw {
		raw = append(raw, line.Text)
	}
	text := strings.Join(raw, "\n")
	for _, want := range []string{"kind: Registry Run", `recorded in: HKCU\`, `image: C:\Users\sam\AppData\Roaming\svchost.exe`, "  sha256: ", "  signature: none",
		"VirusTotal: known=yes malicious=23 suspicious=2", "finding: startup-system-name (first; ref startup:", "ATT&CK T1036.005, T1547.001"} {
		if !strings.Contains(text, want) {
			t.Errorf("the impostor's evidence lacks %q:\n%s", want, text)
		}
	}
	for field, want := range map[string]string{"signed": "no", "vt": "flagged", "level": "first", "windows": "no", "kind": "Registry Run"} {
		if got := impostor.Fields[field]; len(got) == 0 || got[0] != want {
			t.Errorf("the impostor's %s is %v, want %s", field, got, want)
		}
	}

	// The search finds what the fields say.
	find := func(page *Page, search string) []string {
		q, err := query.Parse(search)
		if err != nil {
			t.Fatalf("%q: %v", search, err)
		}
		var names []string
		for _, row := range page.Rows {
			if q.Match(query.Record{Fields: row.Fields, Text: row.Text}) {
				names = append(names, row.Cells[1])
			}
		}
		return names
	}
	// PhotoSorter counts as flagged: one engine suspects it.
	if got := find(&b.Startup, "signed:no vt:flagged"); strings.Join(got, ",") != "Windows Host Service,PhotoSorter" {
		t.Errorf("signed:no vt:flagged found %v", got)
	}
	if got := find(&b.Startup, "signed:no vt:flagged level:first"); strings.Join(got, ",") != "Windows Host Service" {
		t.Errorf("signed:no vt:flagged level:first found %v", got)
	}
	if got := find(&b.Startup, "attack:T1053.005"); strings.Join(got, ",") != `\Updater\Check` {
		t.Errorf("attack:T1053.005 found %v", got)
	}
	if got := find(&b.Running, "pid:5600"); len(got) != 1 || !strings.Contains(got[0], "FabrikamLauncherSetup.exe") {
		t.Errorf("pid:5600 found %v", got)
	}
	if got := find(&b.Connections, "reach:internet -windows:yes"); len(got) == 0 {
		t.Error("no connection to the internet outside Windows was found")
	}
	if got := find(&b.Worth, "rule:virustotal"); len(got) != 2 {
		t.Errorf("rule:virustotal found %v on the Worth a look page", got)
	}
	// Words with no field search the evidence too, such as a fingerprint.
	print := s.Fingerprint(`C:\Users\sam\AppData\Roaming\svchost.exe`)
	if got := find(&b.Startup, print[:16]); len(got) == 0 {
		t.Error("a fingerprint typed into the search finds nothing")
	}
}
