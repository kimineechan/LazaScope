package report

import (
	"encoding/json"
	"strings"
	"testing"

	"lazascope/internal/rules"
)

// Every form of the report names the ATT&CK techniques a finding is a trace
// of, and says which version of ATT&CK the numbers come from.
func TestReportsNameTechniques(t *testing.T) {
	b := book(nil)
	var document struct {
		AttackVersion string
		Findings      []struct {
			Rule, Subject string
			Attack        []struct{ ID, Name string }
		}
	}
	if err := json.Unmarshal(JSON(b, "1.0.0"), &document); err != nil {
		t.Fatal(err)
	}
	if document.AttackVersion != rules.AttackVersion {
		t.Errorf("the data names ATT&CK version %q, want %q", document.AttackVersion, rules.AttackVersion)
	}
	tagged := 0
	for _, f := range document.Findings {
		for _, technique := range f.Attack {
			tagged++
			if technique.ID == "" || technique.Name == "" {
				t.Errorf("%s (%s) carries a technique without a number or a name: %+v", f.Rule, f.Subject, technique)
			}
		}
		if f.Rule == "startup-system-name" && len(f.Attack) == 0 {
			t.Errorf("a program named like a part of Windows carries no technique")
		}
	}
	if tagged == 0 {
		t.Fatal("no finding on the made-up PC carries a technique")
	}

	page := string(HTML(b, "1.0.0"))
	text := Text(b, "1.0.0")
	for _, f := range b.Findings {
		line := rules.Attack(f.Attack)
		if line == "" {
			continue
		}
		if !strings.Contains(text, "MITRE ATT&CK "+rules.AttackVersion+": "+line) {
			t.Errorf("the text report lacks the techniques of %s: %s", f.Rule, line)
		}
		if !strings.Contains(page, "MITRE ATT&amp;CK "+rules.AttackVersion+": ") {
			t.Errorf("the web page lacks the techniques of %s", f.Rule)
		}
	}
}
