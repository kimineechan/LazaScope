package winpath

import "testing"

func TestParts(t *testing.T) {
	for _, test := range []struct{ path, base, dir, ext, stem string }{
		{`C:\Windows\System32\CMD.EXE`, "CMD.EXE", `C:\Windows\System32`, ".exe", "cmd"},
		{`C:\thing.dll`, "thing.dll", `C:\`, ".dll", "thing"},
		{`C:/Program Files/App/app.exe`, "app.exe", `C:\Program Files\App`, ".exe", "app"},
		{`notepad`, "notepad", "", "", "notepad"},
		{`\\server\share\tool.exe`, "tool.exe", `\\server\share`, ".exe", "tool"},
		{`C:\Users\sam\.config`, ".config", `C:\Users\sam`, "", ".config"},
		{`C:\folder\`, "folder", `C:\`, "", "folder"},
		{`C:tool.exe`, "tool.exe", "", ".exe", "tool"},
	} {
		if got := Base(test.path); got != test.base {
			t.Errorf("Base(%q) = %q, want %q", test.path, got, test.base)
		}
		if got := Dir(test.path); got != test.dir {
			t.Errorf("Dir(%q) = %q, want %q", test.path, got, test.dir)
		}
		if got := Ext(test.path); got != test.ext {
			t.Errorf("Ext(%q) = %q, want %q", test.path, got, test.ext)
		}
		if got := Stem(test.path); got != test.stem {
			t.Errorf("Stem(%q) = %q, want %q", test.path, got, test.stem)
		}
	}
}

func TestUnder(t *testing.T) {
	for _, test := range []struct {
		path, folder string
		want         bool
	}{
		{`C:\Windows\System32\cmd.exe`, `C:\Windows`, true},
		{`c:\windows\system32\cmd.exe`, `C:\WINDOWS\`, true},
		{`C:\Windows`, `C:\Windows`, false},               // a folder is not inside itself
		{`C:\WindowsApps\thing.exe`, `C:\Windows`, false}, // a name that only starts the same
		{`C:\Users\sam\a.exe`, `C:\`, true},
		{`D:\Users\sam\a.exe`, `C:\Users`, false},
		{`C:\Users\sam\a.exe`, ``, false},
	} {
		if got := Under(test.path, test.folder); got != test.want {
			t.Errorf("Under(%q, %q) = %v, want %v", test.path, test.folder, got, test.want)
		}
	}
}

func TestInSameHasJoinAbsolute(t *testing.T) {
	if !In(`C:\Windows\explorer.exe`, `c:\windows\`) || In(`C:\Windows\System32\cmd.exe`, `C:\Windows`) || In(`C:\a.exe`, "") {
		t.Error("In is true only for a file directly in the folder")
	}
	if !Same(`C:\Windows\`, `c:/windows`) || Same(`C:\Windows`, `C:\Windows2`) {
		t.Error("Same compares paths without regard to capitals or the kind of slash")
	}
	if !Has(`C:\Users\sam\Downloads\tool.exe`, "downloads") || Has(`C:\Users\sam\Downloads2\tool.exe`, "Downloads") || Has(`C:\tools\downloads`, "downloads") {
		t.Error("Has finds a folder of that name on the way to the file, and nothing else")
	}
	if got := Join(`C:\Windows\`, "System32"); got != `C:\Windows\System32` {
		t.Errorf("Join gave %q", got)
	}
	if got := Join(`C:\`, "a.exe"); got != `C:\a.exe` {
		t.Errorf("Join at the top of a drive gave %q", got)
	}
	if !Absolute(`C:\a.exe`) || !Absolute(`\\server\share\a.exe`) || Absolute(`a.exe`) || Absolute(`System32\a.exe`) || Absolute(`C:a.exe`) {
		t.Error("Absolute is true for a path from a drive or a share")
	}
}
