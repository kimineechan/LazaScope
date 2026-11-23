package scripts

import (
	"strings"
	"testing"
)

func TestIs(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Users\sam\start.cmd`: true, `C:\Tools\job.PS1`: true, `C:\a\b.vbs`: true, `D:\x\sync.mjs`: true, `C:\x\run.bat`: true, `tool.py`: true,
		`C:\Program Files\App\app.exe`: false, `C:\notes.txt`: false, `C:\folder.ps1\file`: false, `C:\x\.ps1`: false, ``: false, `C:\x\noending`: false,
	} {
		if got := Is(path); got != want {
			t.Errorf("Is(%q) = %v", path, got)
		}
	}
	if !Encoded(`C:\x\a.VBE`) || !Encoded(`a.jse`) || Encoded(`a.vbs`) || Encoded(``) {
		t.Error("the encoded kinds are not told apart")
	}
}

func signsOf(text string) string { return strings.Join(Read(text, 5).Signs, " | ") }

func TestSigns(t *testing.T) {
	for _, test := range []struct{ text, want string }{
		// Everyday scripts.
		{"@echo off\r\nstart \"\" \"C:\\Program Files\\Notes\\notes.exe\"\r\n", ""},
		{"Write-Host 'Hello'\nGet-Date", ""},
		{"Remove-Item $env:TEMP\\*.log -Recurse", "It deletes files or folders."},
		{"reg add HKCU\\Software\\Thing /v Colour /d blue /f", "It changes settings in the registry, Windows' settings database."},
		// The things an unwanted script does.
		{"Add-MpPreference -ExclusionPath C:\\Users\\Public", "It changes Microsoft Defender's settings."},
		{"vssadmin delete shadows /all /quiet", "It removes the backup copies of files that Windows keeps."},
		{"wevtutil cl System", "It clears Windows' logs."},
		{"netsh advfirewall set allprofiles state off", "It changes the firewall."},
		{"net user helper Pass123 /add\r\nnet localgroup administrators helper /add", "It adds or changes user accounts."},
		{"IEX (New-Object Net.WebClient).DownloadString('https://example.com/a.ps1')", "It fetches something from the internet. | It runs a piece of text as commands, so what it does can change without the file changing."},
		{"$b = [Convert]::FromBase64String($x)", "It unpacks text that is stored in an encoded form."},
		{"schtasks /create /tn Updater /tr C:\\x.exe /sc onlogon", "It changes what starts with Windows."},
		{"Stop-Service WinDefend", "It stops or switches off services."},
		{"Get-AppxPackage *xbox* | Remove-AppxPackage", "It removes apps or parts of Windows."},
		{"powershell -WindowStyle Hidden -File a.ps1", "It asks PowerShell to work without showing a window."},
		// Other languages.
		{"const r = await fetch('https://example.com/data.json')", "It fetches something from the internet."},
		{"import urllib.request\nurllib.request.urlopen('https://example.com')", "It fetches something from the internet."},
		{"Set x = CreateObject(\"MSXML2.XMLHTTP\")", "It fetches something from the internet."},
		{"fs.rmSync(dir, {recursive: true})", "It deletes files or folders."},
		// Words broken up to hide them are put back together first.
		{"Add-Mp^Pref`erence -ExclusionPath C:\\", "It changes Microsoft Defender's settings."},
		{"SET-MPPREFERENCE   -DisableRealtimeMonitoring $true", "It changes Microsoft Defender's settings."},
		// Words that only look alike stay quiet.
		{"echo The curling club meets on Friday", ""},
		{"rem evaluation copy", ""},
	} {
		if got := signsOf(test.text); got != test.want {
			t.Errorf("%q\n   got %q\n  want %q", test.text, got, test.want)
		}
	}
	// Every sign is a whole sentence, and none passes judgement.
	for _, sign := range signs {
		if !strings.HasPrefix(sign.says, "It ") || !strings.HasSuffix(sign.says, ".") || len(sign.words) == 0 {
			t.Errorf("the sign %q is not a sentence with words to look for", sign.says)
		}
		for _, banned := range []string{"virus", "malware", "infect", "malicious", "dangerous"} {
			if strings.Contains(strings.ToLower(sign.says), banned) {
				t.Errorf("the sign %q gives a verdict", sign.says)
			}
		}
		for _, word := range sign.words {
			if word != strings.ToLower(word) {
				t.Errorf("the word %q of %q would never match: it is not in small letters", word, sign.says)
			}
		}
	}
}

func TestLines(t *testing.T) {
	r := Read("<#\r\n  Tidies the PC.\r\n#>\r\n\r\n\tparam($Days)\r\n\r\nGet-ChildItem\r\nlast", 4)
	want := []string{"<#", "  Tidies the PC.", "#>", "    param($Days)"}
	if strings.Join(r.Lines, "|") != strings.Join(want, "|") || !r.More {
		t.Errorf("got %q, more %v", r.Lines, r.More)
	}
	if r := Read("one\ntwo", 4); len(r.Lines) != 2 || r.More {
		t.Errorf("a short script: %q, more %v", r.Lines, r.More)
	}
	if r := Read("", 4); len(r.Lines) != 0 || r.More || len(r.Signs) != 0 {
		t.Errorf("an empty script: %+v", r)
	}
	// A very long line is cut, and a character that would not show is dotted.
	long := Read(strings.Repeat("x", 400)+"\nbell\x07here", 4)
	if len([]rune(long.Lines[0])) != 150 || !strings.HasSuffix(long.Lines[0], "...") || long.Lines[1] != "bell.here" {
		t.Errorf("got %q", long.Lines)
	}
}

func TestText(t *testing.T) {
	plain, ok := Text([]byte("echo hello\r\n"))
	if !ok || plain != "echo hello\r\n" {
		t.Errorf("plain text: %q, %v", plain, ok)
	}
	marked, ok := Text([]byte{0xEF, 0xBB, 0xBF, 'h', 'i'})
	if !ok || marked != "hi" {
		t.Errorf("text with a mark at the start: %q, %v", marked, ok)
	}
	wideLittle, ok := Text([]byte{0xFF, 0xFE, 'h', 0, 'i', 0})
	if !ok || wideLittle != "hi" {
		t.Errorf("two bytes to a letter: %q, %v", wideLittle, ok)
	}
	wideBig, ok := Text([]byte{0xFE, 0xFF, 0, 'h', 0, 'i'})
	if !ok || wideBig != "hi" {
		t.Errorf("two bytes to a letter, the other way round: %q, %v", wideBig, ok)
	}
	unmarked, ok := Text([]byte{'e', 0, 'c', 0, 'h', 0, 'o', 0, ' ', 0, 'x', 0})
	if !ok || unmarked != "echo x" {
		t.Errorf("two bytes to a letter with no mark: %q, %v", unmarked, ok)
	}
	if _, ok := Text([]byte{'M', 'Z', 0x90, 0, 3, 0, 0, 0, 4}); ok {
		t.Error("a program was taken for text")
	}
	if text, ok := Text(nil); !ok || text != "" {
		t.Errorf("an empty file: %q, %v", text, ok)
	}
}
