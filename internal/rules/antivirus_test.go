package rules

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

// asked marks a file as one the antivirus was asked about.
func asked(f model.File, harmful bool, name string) model.File {
	f.Opinion = model.Opinion{Asked: true, Harmful: harmful, Name: name}
	return f
}

func init() {
	changes = append(changes, []change{
		// What the installed antivirus says when it is asked.
		{"the antivirus has nothing against a script that starts by itself", add(entry(model.RunKey, "Job", asked(script(`C:\Program Files\Job\job.cmd`), false, ""))), ""},
		{"the antivirus calls a script that starts by itself harmful", add(entry(model.RunKey, "Job", asked(script(`C:\Program Files\Job\job.cmd`), true, "Trojan:BAT/Example.A"))), "startup-antivirus-objects:high"},
		{"the same script, switched off in Task Manager", add(off(entry(model.RunKey, "Job", asked(script(`C:\Program Files\Job\job.cmd`), true, "Trojan:BAT/Example.A")))), ""},
		{"the antivirus calls the hidden command of a start-up entry harmful", func(s *model.Snapshot) {
			e := through(model.RunKey, "Upd", encodedRun, windows(powershell), windows(powershell))
			e.Said = model.Opinion{Asked: true, Harmful: true}
			s.Startup = append(s.Startup, e)
		}, "startup-antivirus-objects:high startup-scrambled-command:high"},
		{"the antivirus has nothing against a hidden command", func(s *model.Snapshot) {
			e := through(model.RunKey, "Upd", encodedRun, windows(powershell), windows(powershell))
			e.Said = model.Opinion{Asked: true}
			s.Startup = append(s.Startup, e)
		}, "startup-scrambled-command:high"},
		{"the antivirus calls a running command harmful", run(model.Process{PID: 9000, Name: "powershell.exe", File: windows(powershell), Command: encodedRun,
			Said: model.Opinion{Asked: true, Harmful: true, Name: "TrojanDownloader:PowerShell/Example.B!amsi"}}), "running-antivirus-objects:high running-scrambled-command:medium"},

		// The harmless sample used to test an antivirus is not a finding of anything.
		{"Defender's log holds only tests of the antivirus", guard(func(g *model.Guard) {
			g.Detections = []model.Detection{{When: now.AddDate(0, 0, -1), Threat: "Example:Win32/MpTest!amsi", Source: "AMSI", Process: `C:\Tools\LazaScope.exe`}, {When: now.AddDate(0, 0, -2), Threat: "Example:DOS/EICAR_Test_File"}}
		}), "defender-found-something:low"},
		{"Defender's log holds a test and a real detection", guard(func(g *model.Guard) {
			g.Detections = []model.Detection{{When: now.AddDate(0, 0, -1), Threat: "Example:Win32/MpTest!amsi"}, found(3, "Trojan:Win32/Example.A!ml", `C:\Users\sam\Downloads\free.exe`, "Quarantine")}
		}), "defender-found-something:medium"},
	}...)
}

func TestAntivirusWording(t *testing.T) {
	// A script in a place the antivirus was told to skip.
	s := healthy()
	s.Engine = "Microsoft Defender Antivirus"
	s.Guard.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `D:\Skipped`}}
	s.Startup = append(s.Startup, entry(model.ScheduledTask, `\Job`, asked(script(`D:\Skipped\job.ps1`), true, "Trojan:PowerShell/Example.A")))
	var f Finding
	for _, finding := range Check(s) {
		if finding.Rule == "startup-antivirus-objects" {
			f = finding
		}
	}
	for _, want := range []string{
		`Microsoft Defender Antivirus, asked just now, calls the script D:\Skipped\job.ps1 harmful and names it Trojan:PowerShell/Example.A.`,
		"That is the antivirus's judgement and not LazaScope's.",
		`The script sits in D:\Skipped, a place the antivirus was told to skip, which is why it was never checked by itself.`,
	} {
		if !strings.Contains(f.Reason, want) {
			t.Errorf("the reason lacks %q:\n%s", want, f.Reason)
		}
	}
	said := ""
	for _, fact := range f.Facts {
		if fact.Label == "The antivirus, asked just now" {
			said = fact.Value
		}
	}
	if said != "Calls it harmful" {
		t.Errorf("the facts say of the antivirus: %q", said)
	}

	// With no antivirus named, the sentence still stands.
	s.Engine = ""
	if got := Engine(s); got != "The antivirus on this PC" {
		t.Errorf("the antivirus is called %q", got)
	}

	// A hidden command: the reason says why the antivirus had not met it.
	s = healthy()
	e := through(model.RunKey, "Upd", encodedRun, windows(powershell), windows(powershell))
	e.Said = model.Opinion{Asked: true, Harmful: true}
	s.Startup = append(s.Startup, e)
	for _, finding := range Check(s) {
		if finding.Rule == "startup-antivirus-objects" && !strings.Contains(finding.Reason, "calls the commands carried on this entry's line harmful. That is the antivirus's judgement and not LazaScope's. A command kept in the registry or in a task is not a file") {
			t.Errorf("the reason for a hidden command:\n%s", finding.Reason)
		}
	}

	// A test of the antivirus is said to be one, and names who asked.
	s = healthy()
	s.Guard.Detections = []model.Detection{{When: now.AddDate(0, 0, -1), Threat: "Example:Win32/MpTest!amsi", Source: "AMSI", Process: `C:\Tools\LazaScope.exe`}}
	f = Check(s)[0]
	if f.Subject != "A test of the antivirus" || !strings.Contains(f.Reason, "it passed. Nothing harmful was found.") ||
		f.Facts[0].Value != `Example:Win32/MpTest!amsi. Found when C:\Tools\LazaScope.exe asked the antivirus about some content` {
		t.Errorf("the finding for a test of the antivirus: %+v", f)
	}
	for name, want := range map[string]bool{"Virus:Win32/MpTest!amsi": true, "Virus:DOS/EICAR_Test_File": true, "Trojan:Win32/Example.A": false, "": false} {
		if TestSample(name) != want {
			t.Errorf("TestSample(%q) = %v", name, !want)
		}
	}
}

// The commands a line carries for a scripting tool: decoded when encoded,
// and nothing for a line that names a file.
func TestCarried(t *testing.T) {
	const file = `C:\ProgramData\Tidy\Scripts\tidy.ps1`
	for _, test := range []struct{ line, want string }{
		{encodedRun, "IEX"},
		{`powershell.exe -NoProfile -Command "Get-Date; Write-Host hello"`, "Get-Date; Write-Host hello"},
		{`powershell.exe -File ` + file, ""},
		{`powershell.exe -Command "iex([IO.File]::ReadAllText('` + file + `'))"`, ""},
		{`"C:\Program Files\Notes\notes.exe" --tray`, ""},
		{``, ""},
	} {
		got := Carried(powershell, test.line)
		if (test.want == "") != (got == "") || !strings.HasPrefix(got, test.want) {
			t.Errorf("Carried(%q) = %q, want it to begin %q", test.line, got, test.want)
		}
	}
	// A tool other than PowerShell that is made to run script written on the line.
	if got := Carried(`C:\Windows\System32\mshta.exe`, `mshta.exe javascript:close()`); got != `mshta.exe javascript:close()` {
		t.Errorf("a line of script for another tool gave %q", got)
	}
}
