package virustotal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

func answerAt(asked time.Time) model.Reputation {
	return model.Reputation{Asked: asked, Known: true, Undetected: 70}
}

// A fingerprint is used again only while the file keeps its size and time.
func TestPrints(t *testing.T) {
	m := OpenMemory("")
	when := time.Date(2026, 11, 1, 9, 30, 0, 123456789, time.UTC)
	m.KeepPrint(`C:\Tools\Tool.exe`, 1000, when, testPrint)
	m.KeepPrint(`C:\Tools\bad.exe`, 1000, when, "not a fingerprint")
	if print, ok := m.Print(`c:\tools\TOOL.EXE`, 1000, when); !ok || print != testPrint {
		t.Errorf("the same file gave %q, %v", print, ok)
	}
	if _, ok := m.Print(`C:\Tools\Tool.exe`, 1001, when); ok {
		t.Error("a file of another size kept its fingerprint")
	}
	if _, ok := m.Print(`C:\Tools\Tool.exe`, 1000, when.Add(time.Nanosecond)); ok {
		t.Error("a file changed since kept its fingerprint")
	}
	if _, ok := m.Print(`C:\Tools\bad.exe`, 1000, when); ok {
		t.Error("something that is not a fingerprint was kept")
	}
}

// A memory is saved whole and read back, and a damaged one starts afresh.
func TestMemoryOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LazaScope", "virustotal.json")
	m := OpenMemory(path)
	when := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)
	m.KeepPrint(`C:\Tools\Tool.exe`, 1000, when, testPrint)
	m.Keep(testPrint, model.Reputation{Asked: when, Known: true, Malicious: 2, Undetected: 60, Names: []model.EngineName{{Engine: "Northwind AV", Name: "Trojan.Example"}}})
	m.SetAfterEachLook(true)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), testKey) {
		t.Error("the memory holds a key")
	}
	again := OpenMemory(path)
	r, ok := again.Answer(strings.ToUpper(testPrint))
	if !ok || r.Malicious != 2 || len(r.Names) != 1 || !r.Asked.Equal(when) {
		t.Errorf("read back %+v, %v", r, ok)
	}
	if print, ok := again.Print(`C:\Tools\Tool.exe`, 1000, when); !ok || print != testPrint {
		t.Error("the fingerprint did not come back")
	}
	if !again.AfterEachLook() || again.Answers() != 1 {
		t.Error("the setting or the count did not come back")
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Error("the half-written file was left behind")
	}

	os.WriteFile(path, []byte("{damaged"), 0o600)
	if damaged := OpenMemory(path); damaged.Answers() != 0 || damaged.AfterEachLook() {
		t.Error("a damaged memory was not started afresh")
	}
	if err := again.Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) || again.Answers() != 0 {
		t.Error("Forget left the memory behind")
	}
	if err := again.Forget(); err != nil {
		t.Errorf("forgetting twice gave %v", err)
	}
}

// The memory never grows past its limit: the oldest answers go first.
func TestMemoryLimit(t *testing.T) {
	m := OpenMemory("")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	hex := "0123456789abcdef"
	print := func(i int) string {
		b := []byte(strings.Repeat("0", 64))
		for j := 0; j < 8; j++ {
			b[63-j] = hex[(i>>(4*j))&15]
		}
		return string(b)
	}
	for i := 0; i <= keep; i++ {
		m.Keep(print(i), answerAt(start.Add(time.Duration(i)*time.Minute)))
	}
	if m.Answers() != keep {
		t.Fatalf("holds %d answers", m.Answers())
	}
	if _, ok := m.Answer(print(0)); ok {
		t.Error("the oldest answer was kept")
	}
	if _, ok := m.Answer(print(keep)); !ok {
		t.Error("the newest answer was dropped")
	}
}

// Apply puts what is known into a look, and only for files that have not changed.
func TestApply(t *testing.T) {
	when := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)
	m := OpenMemory("")
	m.KeepPrint(`C:\Tools\Tool.exe`, 1000, when, testPrint)
	m.KeepPrint(`C:\Tools\Changed.exe`, 1000, when, otherHash)
	m.Keep(testPrint, answerAt(when))
	m.Keep(otherHash, answerAt(when))
	tool := model.File{Path: `C:\Tools\Tool.exe`, Exists: true, Program: true, Size: 1000, Modified: when}
	changed := model.File{Path: `C:\Tools\Changed.exe`, Exists: true, Program: true, Size: 2000, Modified: when}
	s := &model.Snapshot{
		Startup:   []model.Startup{{Kind: model.RunKey, Name: "Tool", Program: tool, Target: tool, Enabled: true}},
		Processes: []model.Process{{PID: 10, Name: "Changed.exe", File: changed}, {PID: 11, Name: "Tool.exe", File: tool}},
	}
	if n := m.Apply(s); n != 1 {
		t.Errorf("%d files have an answer, want 1", n)
	}
	if r, ok := s.Reputation(tool.Path); !ok || !r.Known {
		t.Error("the unchanged file has no answer")
	}
	if _, ok := s.Reputation(changed.Path); ok {
		t.Error("a file that changed since was given the old answer")
	}
	if s.Fingerprint(changed.Path) != "" {
		t.Error("a file that changed since was given the old fingerprint")
	}
}
