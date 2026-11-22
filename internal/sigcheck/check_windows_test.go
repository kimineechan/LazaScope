//go:build windows

package sigcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func system(name string) string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", name)
}

// Windows' own programs must come out as signed by Microsoft. This is the
// test that fails if catalogues are not looked in, because some of these
// files carry no signature of their own.
func TestWindowsFilesAreSigned(t *testing.T) {
	checker := New()
	defer checker.Close()
	catalogued := 0
	for _, name := range []string{"cmd.exe", "notepad.exe", "whoami.exe", "kernel32.dll", "ntdll.dll", "svchost.exe", "drivers\\ntfs.sys"} {
		path := system(name)
		if _, err := os.Stat(path); err != nil {
			continue // not every edition of Windows has every file
		}
		r := checker.Check(path)
		if r.Status != Signed || !r.FromMicrosoft() {
			t.Errorf("%s: got %v by %q (%s), want signed by Microsoft", name, r.Status, r.Signer, r.Problem)
		}
		if r.Source == Catalogue {
			catalogued++
			if r.Catalogue == "" {
				t.Errorf("%s: signed through a catalogue, but the catalogue is not named", name)
			}
		}
	}
	if catalogued == 0 {
		t.Error("none of the files was found through a catalogue; the catalogue lookup is not working")
	}
}

// A program built here has no signature at all.
func TestUnsignedProgram(t *testing.T) {
	checker := New()
	defer checker.Close()
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if r := checker.Check(self); r.Status != Unsigned || r.Signer != "" || r.Trusted() {
		t.Errorf("the test program itself: got %v by %q, want not signed", r.Status, r.Signer)
	}
}

func TestMissingFileAndFolder(t *testing.T) {
	checker := New()
	defer checker.Close()
	if r := checker.Check(filepath.Join(t.TempDir(), "nothing.exe")); r.Status != Unknown || r.Problem == "" {
		t.Errorf("a missing file: got %v %q, want not checked with a reason", r.Status, r.Problem)
	}
	if r := checker.Check(t.TempDir()); r.Status != Unknown {
		t.Errorf("a folder: got %v, want not checked", r.Status)
	}
	if r := checker.Check(""); r.Status != Unknown {
		t.Errorf("no name: got %v, want not checked", r.Status)
	}
}

// copyOf writes a copy of a file under another name and returns its path.
func copyOf(t *testing.T, source, name string, change func([]byte)) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Skip(err)
	}
	if change != nil {
		change(data)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A catalogue lists a file by its fingerprint, not by its name or place. So
// a copy of a Windows program under another name, somewhere else, is still
// Microsoft's file. Rules that look for a disguise must not lean on the
// signature alone.
func TestRenamedCopyKeepsItsCatalogueSignature(t *testing.T) {
	checker := New()
	defer checker.Close()
	for _, name := range []string{"notepad.exe", "cmd.exe", "whoami.exe"} {
		if r := checker.Check(system(name)); r.Status != Signed || r.Source != Catalogue {
			continue
		}
		disguised := copyOf(t, system(name), "svchost.exe", nil)
		if r := checker.Check(disguised); r.Status != Signed || r.Source != Catalogue || !r.FromMicrosoft() {
			t.Errorf("a renamed copy of %s: got %v %v by %q, want signed through a catalogue by Microsoft", name, r.Status, r.Source, r.Signer)
		}
		return
	}
	t.Skip("no catalogue-signed program to copy on this version of Windows")
}

// One changed byte must break a signature.
func TestChangedFileFailsItsSignature(t *testing.T) {
	checker := New()
	defer checker.Close()
	for _, source := range []string{filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), system("ntdll.dll"), system("kernel32.dll")} {
		if r := checker.Check(source); r.Status != Signed || r.Source != Embedded {
			continue
		}
		changed := copyOf(t, source, "changed.exe", func(data []byte) { data[len(data)/2] ^= 0xFF })
		r := checker.Check(changed)
		if r.Status != Invalid || !r.Changed() || r.Trusted() || r.Problem == "" {
			t.Errorf("a changed copy of %s: got %v (0x%08X) %q, want a signature that does not hold because the file changed", filepath.Base(source), r.Status, r.Code, r.Problem)
		}
		return
	}
	t.Skip("no program with a signature of its own to change on this version of Windows")
}

func TestAnswersAreRemembered(t *testing.T) {
	checker := New()
	defer checker.Close()
	path := system("cmd.exe")
	first := checker.Check(path)
	second := checker.Check(path)
	if first != second {
		t.Errorf("the same file gave two answers: %+v and %+v", first, second)
	}
	if asked, read := checker.Counts(); asked != 2 || read != 1 {
		t.Errorf("asked %d times and read the file %d times, want 2 and 1", asked, read)
	}
}
