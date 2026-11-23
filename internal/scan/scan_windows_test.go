//go:build windows

package scan

import (
	"lazascope/internal/sigcheck"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

// A collector that goes wrong must leave a note and nothing else: the look
// carries on, and the part it was reading is said to be unread.
func TestGuard(t *testing.T) {
	var gaps []model.Gap
	var list []int
	guard(model.RunningNow, "What is running", &gaps, func() {
		var none []int
		list = append(list, none[3]) // goes wrong half way
	})
	if len(list) != 0 {
		t.Errorf("a collector that failed left %d results", len(list))
	}
	if len(gaps) != 1 || gaps[0].Area != model.RunningNow {
		t.Fatalf("got %+v, want one note for what is running", gaps)
	}
	for _, want := range []string{"What is running could not be read", "an error inside LazaScope itself", "index out of range", "Please report it."} {
		if !strings.Contains(gaps[0].What, want) {
			t.Errorf("the note lacks %q: %s", want, gaps[0].What)
		}
	}
	// A collector that works keeps its own notes and gains none.
	gaps = nil
	guard(model.Protection, "The state of the protections", &gaps, func() {
		gaps = []model.Gap{{Area: model.Protection, What: "The exclusions could not be read."}}
	})
	if len(gaps) != 1 || gaps[0].What != "The exclusions could not be read." {
		t.Errorf("got %+v", gaps)
	}
}

// Judging a look works out the fingerprint of each file a finding is about.
func TestJudgeFingerprints(t *testing.T) {
	folder := t.TempDir()
	flagged := filepath.Join(folder, "tool.exe")
	if err := os.WriteFile(flagged, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	quiet := filepath.Join(folder, "fine.exe")
	if err := os.WriteFile(quiet, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	unsigned := model.File{Path: flagged, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}
	signed := model.File{Path: quiet, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Signed, Source: sigcheck.Embedded, Signer: "Notes Ltd"}}
	gone := model.File{Path: filepath.Join(folder, "gone.exe")}
	s := &model.Snapshot{Taken: time.Now(), Folders: model.Folders{Windows: `C:\Windows`, ProgramFiles: `C:\Program Files`}, Startup: []model.Startup{
		{Kind: model.RunKey, Name: "Tool", Command: flagged, Program: unsigned, Target: unsigned, Enabled: true},
		{Kind: model.RunKey, Name: "Fine", Command: quiet, Program: signed, Target: signed, Enabled: true},
		{Kind: model.RunKey, Name: "Gone", Command: gone.Path, Program: gone, Target: gone, Enabled: true},
	}}
	findings := Judge(s)
	if len(findings) == 0 {
		t.Fatal("the unsigned program was not flagged, so this test proves nothing")
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := s.Fingerprint(flagged); got != abc {
		t.Errorf("the flagged file's fingerprint is %q", got)
	}
	if got := s.Fingerprint(strings.ToUpper(flagged)); got != abc {
		t.Errorf("asked for in capitals, the fingerprint is %q", got)
	}
	if got := s.Fingerprint(quiet); got != "" {
		t.Errorf("a file no finding is about was fingerprinted: %q", got)
	}
	if got := s.Fingerprint(gone.Path); got != "" {
		t.Errorf("a file that is not there has the fingerprint %q", got)
	}
}
