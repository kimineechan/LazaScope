package privacy

import (
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

const (
	windows10   = 19045 // Windows 10 22H2
	windows11a  = 22000 // Windows 11 21H2, before it switched these on by itself
	windows11   = 26100 // Windows 11 24H2
	noSetting   = 0
	switchedOff = 0
)

func TestLSA(t *testing.T) {
	for _, c := range []struct {
		name              string
		setting           uint32
		set, logged, prot bool
		build             int
		want              model.Answer
		note              string // a few words the note must hold, or "" for none
	}{
		{"Windows 11 switched it on by itself, without the setting", noSetting, false, true, true, windows11, model.Yes, "working since Windows last started"},
		{"locked in the firmware, with the setting taken away", switchedOff, true, true, true, windows10, model.Yes, "working since Windows last started"},
		{"switched on and working", 1, true, true, true, windows10, model.Yes, "working since"},
		{"switched on, waiting for a restart", 1, true, true, false, windows10, model.No, "after a restart"},
		{"switched on without the lock on Windows 11, waiting for a restart", 2, true, true, false, windows11, model.No, "after a restart"},
		{"switched on, and the log cannot say", 1, true, false, false, windows10, model.Yes, ""},
		{"switched on without the lock on Windows 11, and the log cannot say", 2, true, false, false, windows11, model.Yes, ""},
		{"the value 2 on Windows 10, which it ignores", 2, true, true, false, windows10, model.No, "Earlier versions need 1"},
		{"the value 2 on Windows 10, and the log cannot say", 2, true, false, false, windows10, model.No, "Earlier versions need 1"},
		{"the value 2 on Windows 11 21H2, which ignores it", 2, true, false, false, windows11a, model.No, "Earlier versions need 1"},
		{"never set on Windows 10", noSetting, false, true, false, windows10, model.No, ""},
		{"never set on Windows 10, and the log cannot say", noSetting, false, false, false, windows10, model.No, ""},
		{"never set on Windows 11, and the log shows it is off", noSetting, false, true, false, windows11, model.No, ""},
		{"never set on Windows 11, and the log cannot say", noSetting, false, false, false, windows11, model.NotKnown, "cannot tell"},
		{"never set on Windows 11 21H2, and the log cannot say", noSetting, false, false, false, windows11a, model.No, ""},
		{"switched off on Windows 11, and the log cannot say", switchedOff, true, false, false, windows11, model.No, ""},
		{"switched off on Windows 11, and the log shows it is off", switchedOff, true, true, false, windows11, model.No, ""},
	} {
		got, note := lsaState(c.setting, c.set, c.logged, c.prot, c.build)
		if got != c.want || !holds(note, c.note) {
			t.Errorf("%s: got %s, %q; want %s with %q", c.name, got, note, c.want, c.note)
		}
	}
}

func TestMemoryIntegrity(t *testing.T) {
	for _, c := range []struct {
		name                string
		setting             uint32
		set, asked, running bool
		want                model.Answer
		note                string
	}{
		{"on and running", 1, true, true, true, model.Yes, ""},
		{"on by Windows 11's default, running without the setting", noSetting, false, true, true, model.Yes, ""},
		{"switched on, waiting for a restart", 1, true, true, false, model.No, "after a restart"},
		{"switched off", switchedOff, true, true, false, model.No, ""},
		{"never set, and not running", noSetting, false, true, false, model.No, ""},
		{"switched on, and the report cannot be read", 1, true, false, false, model.Yes, ""},
		{"switched off, and the report cannot be read", switchedOff, true, false, false, model.No, ""},
		{"never set, and the report cannot be read", noSetting, false, false, false, model.NotKnown, ""},
	} {
		got, note := hvciState(c.setting, c.set, c.asked, c.running)
		if got != c.want || !holds(note, c.note) {
			t.Errorf("%s: got %s, %q; want %s with %q", c.name, got, note, c.want, c.note)
		}
	}
}

func TestBlocklist(t *testing.T) {
	for _, c := range []struct {
		name    string
		setting uint32
		set     bool
		hvci    model.Answer
		build   int
		want    model.Answer
		note    string
	}{
		{"memory integrity applies it", noSetting, false, model.Yes, windows10, model.Yes, "Memory integrity is on"},
		{"memory integrity applies it even when switched off", switchedOff, true, model.Yes, windows11, model.Yes, "Memory integrity is on"},
		{"switched on", 1, true, model.No, windows11, model.Yes, ""},
		{"switched off on Windows 11", switchedOff, true, model.No, windows11, model.No, ""},
		{"Windows 11's default", noSetting, false, model.No, windows11, model.Yes, "unless someone switches it off"},
		{"Windows 11's default, with memory integrity not known", noSetting, false, model.NotKnown, windows11, model.Yes, "unless someone switches it off"},
		{"Windows 10 without memory integrity", noSetting, false, model.No, windows10, model.No, "only while memory integrity is on"},
		{"Windows 11 21H2 without memory integrity", noSetting, false, model.No, windows11a, model.No, "only while memory integrity is on"},
		{"Windows 10, with memory integrity not known", noSetting, false, model.NotKnown, windows10, model.NotKnown, ""},
	} {
		got, note := blocklistState(c.setting, c.set, c.hvci, c.build)
		if got != c.want || !holds(note, c.note) {
			t.Errorf("%s: got %s, %q; want %s with %q", c.name, got, note, c.want, c.note)
		}
	}
}

func TestLSASSStart(t *testing.T) {
	boot := time.Date(2026, 11, 20, 8, 15, 30, 0, time.UTC)
	table := []model.Process{
		{PID: 4, Name: "System", Started: boot.Add(-10 * time.Second)},
		{PID: 9100, Name: "lsass.exe", Session: 1, Started: boot.Add(-time.Hour)}, // a copy in the user's session
		{PID: 1020, Name: "LSASS.EXE", Session: 0, Started: boot},
		{PID: 9200, Name: "lsass.exe", Session: 0, Started: boot.Add(3 * time.Hour)}, // a later one that borrows the name
		{PID: 9300, Name: "lsass.exe", Session: 0},                                   // one whose start Windows did not give
	}
	if got := lsassStart(table); !got.Equal(boot) {
		t.Errorf("got %v, want %v", got, boot)
	}
	if got := lsassStart(table[:2]); !got.IsZero() {
		t.Errorf("with no LSASS in session 0: got %v", got)
	}
}

// holds reports whether a note holds the words wanted, and when none are
// wanted, that there is no note.
func holds(note, words string) bool {
	if words == "" {
		return note == ""
	}
	return strings.Contains(note, words)
}
