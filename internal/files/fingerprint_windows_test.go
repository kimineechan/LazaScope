//go:build windows

package files

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFingerprint(t *testing.T) {
	folder := t.TempDir()
	// The fingerprints of these two are published with the method itself.
	for name, want := range map[string]string{
		"abc":   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	} {
		path := filepath.Join(folder, name)
		content := []byte(name)
		if name == "empty" {
			content = nil
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := Fingerprint(path)
		if err != nil || got != want {
			t.Errorf("the fingerprint of %q is %s (%v), want %s", name, got, err, want)
		}
	}
	if _, err := Fingerprint(filepath.Join(folder, "not there")); err == nil {
		t.Error("a file that is not there has a fingerprint")
	}
	if _, err := Fingerprint(folder); err == nil {
		t.Error("a folder has a fingerprint")
	}
}

// A script that starts by itself is read when it is looked at, and a file
// that only has a script's name is not taken for text.
func TestLookReadsScripts(t *testing.T) {
	folder := t.TempDir()
	script := filepath.Join(folder, "tidy.cmd")
	if err := os.WriteFile(script, []byte("@echo off\r\nrem tidy up\r\ndel /q \"%TEMP%\\*.tmp\"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	notText := filepath.Join(folder, "odd.ps1")
	if err := os.WriteFile(notText, []byte{'P', 'K', 3, 4, 0, 0, 0, 0, 0, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	scrambled := filepath.Join(folder, "hidden.vbe")
	if err := os.WriteFile(scrambled, []byte("#@~^AAAAAA==~"), 0600); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(folder, "notes.txt")
	if err := os.WriteFile(notes, []byte("del /q everything"), 0600); err != nil {
		t.Fatal(err)
	}
	library := Open()
	defer library.Close()

	read := library.Look(script)
	if !read.Exists || read.Program || read.Script == nil {
		t.Fatalf("the batch file was looked at as %+v", read)
	}
	if len(read.Script.Lines) != 3 || read.Script.Lines[1] != "rem tidy up" || read.Script.More || len(read.Script.Signs) != 1 || read.Script.Signs[0] != "It deletes files or folders." {
		t.Errorf("the batch file was read as %+v", read.Script)
	}
	for _, path := range []string{notText, scrambled, notes} {
		if file := library.Look(path); !file.Exists || file.Script != nil {
			t.Errorf("%s was read as a script: %+v", filepath.Base(path), file.Script)
		}
	}
}
