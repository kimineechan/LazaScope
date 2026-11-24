package rules

import (
	"regexp"
	"strings"
	"testing"

	"lazascope/internal/model"
)

// techniqueNumber is how ATT&CK writes a technique's number: T and four
// digits, and for a sub-technique a dot and three more.
var techniqueNumber = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// Every number a rule can name is in the list of techniques, written the
// way ATT&CK writes it, and every technique in the list is named by a rule.
// A number typed wrongly in one place would otherwise go unseen.
func TestTechniquesAreKnown(t *testing.T) {
	for id, name := range techniques {
		if !techniqueNumber.MatchString(id) {
			t.Errorf("%q is not written the way ATT&CK writes a number", id)
		}
		if strings.TrimSpace(name) == "" {
			t.Errorf("%s has no name", id)
		}
	}
	known := map[string]bool{}
	for _, rule := range All() {
		known[rule.ID] = true
	}
	for rule, ids := range attackOf {
		if !known[rule] {
			t.Errorf("techniques are given for %q, which is no rule", rule)
		}
		for _, id := range ids {
			if _, ok := techniques[id]; !ok {
				t.Errorf("%s names %s, which is not in the list of techniques", rule, id)
			}
		}
	}
	for rule := range staying {
		if !known[rule] {
			t.Errorf("%q is said to be about how an entry stays, and is no rule", rule)
		}
	}
	for kind := model.RunKey; kind <= model.BrowserExtension; kind++ {
		id := kindTechnique(kind)
		if _, ok := techniques[id]; !ok {
			t.Errorf("the way of starting %q has the technique %q, which is not in the list", kind, id)
		}
	}
	covered := Covered()
	for id := range techniques {
		if len(covered[id]) == 0 {
			t.Errorf("%s is in the list, but no rule names it", id)
		}
	}
	for id := range covered {
		if _, ok := techniques[id]; !ok {
			t.Errorf("a rule names %s, which is not in the list", id)
		}
	}
	if AttackVersion == "" {
		t.Error("the version of ATT&CK the numbers come from is not said")
	}
}

// A finding carries the techniques of its rule, then the technique of the
// way the entry it is about starts.
func TestFindingsCarryTechniques(t *testing.T) {
	debugger := func(subject string) model.Startup {
		e := entry(model.DebuggerSetting, subject, windows(`C:\Windows\System32\cmd.exe`))
		e.Subject = subject
		return e
	}
	cases := []struct {
		what   string
		change func(*model.Snapshot)
		rule   string
		want   string
	}{
		{"an unsigned program in the Run list", add(entry(model.RunKey, "Tool", unsigned(`C:\Program Files\Tool\tool.exe`))), "startup-unsigned", "T1547.001"},
		{"an unsigned program in a Startup folder", add(entry(model.StartupFolder, "Tool.lnk", unsigned(`C:\Program Files\Tool\tool.exe`))), "startup-unsigned", "T1547.001"},
		{"an unsigned service", add(entry(model.Service, "Tool", unsigned(`C:\Program Files\Tool\tool.exe`))), "startup-unsigned", "T1543.003"},
		{"an unsigned driver", add(entry(model.Driver, "thing", unsigned(`C:\Windows\System32\drivers\thing.sys`))), "startup-unsigned", "T1543.003"},
		{"a changed program that a task runs", add(entry(model.ScheduledTask, `\Bent`, changed(`C:\Program Files\Bent\bent.exe`))), "startup-altered", "T1554 T1036.001 T1053.005"},
		{"a debugger set for the sticky keys", add(debugger("sethc.exe")), "startup-debugger", "T1546.012 T1546.008"},
		{"a debugger set for Task Manager", add(debugger("taskmgr.exe")), "startup-debugger", "T1546.012"},
		{"User Account Control switched off", func(s *model.Snapshot) { s.Guard.UAC = model.No }, "uac-off", "T1548.002"},
		{"the firewall off on public networks", func(s *model.Snapshot) { s.Guard.FirewallHealth, s.Guard.Firewall[1].On = model.No, model.No }, "firewall-off", "T1686.003"},
	}
	for _, c := range cases {
		s := healthy()
		c.change(s)
		got, seen := "", false
		for _, f := range Check(s) {
			if f.Rule == c.rule {
				got, seen = strings.Join(f.Attack, " "), true
			}
		}
		if !seen {
			t.Errorf("%s: %s did not flag it", c.what, c.rule)
			continue
		}
		if got != c.want {
			t.Errorf("%s: the finding carries %q, want %q", c.what, got, c.want)
		}
	}
}

// A weakness is not a technique: an unencrypted disk carries no number.
func TestWeaknessCarriesNone(t *testing.T) {
	for _, rule := range []string{"disk-not-encrypted", "updates-old", "secure-boot-off"} {
		if note := AttackNote(rule); note != "" {
			t.Errorf("%s names techniques: %s", rule, note)
		}
	}
}

func TestAttackLine(t *testing.T) {
	if got := Attack([]string{"T1547.001", "T9999", "T1053.005"}); got != "T1547.001 Registry Run Keys / Startup Folder; T1053.005 Scheduled Task" {
		t.Errorf("got %q", got)
	}
	if got := Attack(nil); got != "" {
		t.Errorf("no techniques gave %q", got)
	}
	if got := AttackNote("startup-unsigned"); got != "and the technique of the way the entry starts" {
		t.Errorf("startup-unsigned: %q", got)
	}
	if got := strings.Join(Named("startup-debugger"), " "); got != "T1546.008 T1546.012" {
		t.Errorf("startup-debugger names %q", got)
	}
}
