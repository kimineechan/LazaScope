package model

import (
	"fmt"
	"strings"
	"testing"

	"lazascope/internal/sigcheck"
)

func TestFamily(t *testing.T) {
	list := []Process{
		{PID: 4, Name: "System"},
		{PID: 700, Parent: 4, Name: "smss.exe"},
		{PID: 900, Parent: 640, Name: "services.exe", ParentGone: true}, // its starter has closed
		{PID: 1200, Parent: 900, Name: "svchost.exe"},
		{PID: 1100, Parent: 900, Name: "svchost.exe"},
		{PID: 1300, Parent: 900, Name: "spoolsv.exe"},
		{PID: 5000, Parent: 4800, Name: "explorer.exe"}, // its starter is not in the list at all
		{PID: 5100, Parent: 5000, Name: "notepad.exe"},
		{PID: 5200, Parent: 5100, Name: "child.exe"},
		{PID: 6000, Parent: 6001, Name: "ring-a.exe"}, // two that name each other
		{PID: 6001, Parent: 6000, Name: "ring-b.exe"},
	}
	var got []string
	for _, member := range Family(list) {
		got = append(got, fmt.Sprintf("%s%s:%d", strings.Repeat(">", member.Depth), member.Name, member.PID))
	}
	want := "explorer.exe:5000 >notepad.exe:5100 >>child.exe:5200 services.exe:900 >spoolsv.exe:1300 >svchost.exe:1100 >svchost.exe:1200 System:4 >smss.exe:700 ring-a.exe:6000 >ring-b.exe:6001"
	if strings.Join(got, " ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
	if len(Family(nil)) != 0 {
		t.Error("no programs make an empty tree")
	}
}

func TestMaker(t *testing.T) {
	for _, test := range []struct {
		file File
		want string
	}{
		{File{}, ""},
		{File{Path: `C:\gone.exe`}, "File not found"},
		{File{Path: `C:\a.exe`, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Signed, Signer: "Example Ltd"}}, "Example Ltd"},
		{File{Path: `C:\a.exe`, Exists: true, Program: true, Signature: sigcheck.Result{Status: sigcheck.Unsigned}}, "Not signed"},
		// What an unsigned file says of itself is shown as a claim.
		{File{Path: `C:\a.exe`, Exists: true, Program: true, Company: "Microsoft Corporation", Signature: sigcheck.Result{Status: sigcheck.Unsigned}}, "Not signed (says Microsoft Corporation)"},
		{File{Path: `C:\a.exe`, Exists: true, Program: true, Company: "Example Ltd", Signature: sigcheck.Result{Status: sigcheck.Invalid, Signer: "Example Ltd"}}, "Signature not valid (Example Ltd)"},
		{File{Path: `C:\run.vbs`, Exists: true}, "Not a program file"},
	} {
		if got := test.file.Maker(); got != test.want {
			t.Errorf("%+v: got %q, want %q", test.file, got, test.want)
		}
	}
}

func TestStartupWorksAndShown(t *testing.T) {
	entry := Startup{Name: "Audiosrv", Program: File{Path: `C:\Windows\System32\svchost.exe`}, Target: File{Path: `C:\Windows\System32\audiosrv.dll`}}
	if entry.Works().Path != `C:\Windows\System32\audiosrv.dll` || entry.Shown() != "Audiosrv" {
		t.Errorf("got %q and %q", entry.Works().Path, entry.Shown())
	}
	entry.Target, entry.Title = File{}, "Windows Audio"
	if entry.Works().Path != `C:\Windows\System32\svchost.exe` || entry.Shown() != "Windows Audio" {
		t.Errorf("got %q and %q", entry.Works().Path, entry.Shown())
	}
}

func TestNames(t *testing.T) {
	for area := Protection; area < Areas; area++ {
		if area.String() == "" {
			t.Errorf("area %d has no name", area)
		}
	}
	for kind := RunKey; kind <= LoadedLibrary; kind++ {
		if kind.String() == "" || kind.Explain() == "" {
			t.Errorf("start-up kind %d lacks a name or an explanation", kind)
		}
	}
	if Say(true) != Yes || Say(false) != No || NotKnown.String() != "not known" || ThisPC.String() == "" || Internet.String() != "Internet" {
		t.Error("answers and reaches are worded wrongly")
	}
}
