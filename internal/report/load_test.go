package report

import (
	"strings"
	"testing"

	"lazascope/internal/compare"
	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/view"
)

// A report saved as data can be read back in and held against a new look.
// A PC compared with its own report shows nothing new.
func TestLoadAndCompare(t *testing.T) {
	then, err := Load(JSON(book(nil), "1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	made := sample.PC()
	if then.Computer != "STUDY-PC" || len(then.Startup) != len(made.Startup) || len(then.Processes) != len(made.Processes) || len(then.Connections) != len(made.Connections) {
		t.Fatalf("read back as %s with %d, %d and %d entries", then.Computer, len(then.Startup), len(then.Processes), len(then.Connections))
	}
	if then.Taken.IsZero() || then.Guard.UAC != model.Yes || !then.Guard.NameServersRead || len(then.Guard.NameServers) != 1 || !then.Guard.Proxy.Read {
		t.Errorf("the protections read back: %+v", then.Guard)
	}
	extensions := 0
	for _, e := range then.Startup {
		if e.Extension != nil {
			extensions++
			if e.Kind != model.BrowserExtension || e.Extension.ID == "" {
				t.Errorf("an extension read back as %+v", e)
			}
		}
	}
	if extensions != 2 {
		t.Errorf("%d extensions read back, want 2", extensions)
	}

	now := sample.PC()
	compare.Mark(now, then, "the report of that day")
	if c := now.Compared; c.NewStartup+c.NewPrograms+c.NewDoors+len(c.Gone)+len(c.Changed) != 0 {
		t.Errorf("the PC compared with its own report: %+v", c)
	}

	// A week on, something has been added and a setting has changed.
	now = sample.PC()
	now.Startup = append(now.Startup, model.Startup{Kind: model.RunKey, Name: "Updater", Where: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Command: `C:\Users\sam\AppData\Roaming\upd.exe`, Enabled: true})
	now.Guard.RemoteDesktop = model.Yes
	compare.Mark(now, then, "the report of that day")
	b := view.Build(now, rules.Check(now))
	if b.Compared != "Compared with the report of that day: 1 new thing is set to start by itself and 1 setting or entry has changed." {
		t.Errorf("the comparison in a sentence: %q", b.Compared)
	}
	if len(b.Changes) != 1 || b.Changes[0] != "Remote Desktop: was off, is now on." {
		t.Errorf("the changes: %q", b.Changes)
	}
	// The saved reports say so too, in all three forms.
	for name, content := range map[string]string{"web page": string(HTML(b, "1.0.0")), "text": Text(b, "1.0.0"), "data": string(JSON(b, "1.0.0"))} {
		if !strings.Contains(content, "1 new thing is set to start by itself") || !strings.Contains(content, "Remote Desktop: was off, is now on.") {
			t.Errorf("the %s report does not say what the comparison showed", name)
		}
	}
	if !strings.Contains(string(JSON(b, "1.0.0")), `"comparison": {`) || strings.Contains(string(JSON(book(nil), "1.0.0")), `"comparison"`) {
		t.Error("the data names a comparison when there was none, or not when there was one")
	}

	for _, bad := range []string{"", "not json", `{"tool":"Something else","facts":{}}`, `{"tool":"LazaScope 1.0.0"}`, `{"tool":"LazaScope 1.0.0","generated":"last week","facts":{}}`} {
		if _, err := Load([]byte(bad)); err == nil {
			t.Errorf("%q was taken for a report", bad)
		} else if !strings.HasPrefix(err.Error(), "the ") {
			t.Errorf("the refusal of %q does not read as a sentence: %v", bad, err)
		}
	}
	// A mark that some editors put at the start of a file does not spoil it.
	marked := append([]byte{0xEF, 0xBB, 0xBF}, JSON(book(nil), "1.0.0")...)
	if _, err := Load(marked); err != nil {
		t.Errorf("a report with a mark at its start: %v", err)
	}
}
