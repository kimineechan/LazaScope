package rules

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

// What the first look with administrator rights turned up on a real PC.

// A task that makes PowerShell read a named script and run it hides
// nothing. It is a script that starts by itself, and is said to be one.
func TestLoaderIsAScriptNotAScramble(t *testing.T) {
	const file = `C:\ProgramData\Tidy\Scripts\tidy.ps1`
	line := `powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex([IO.File]::ReadAllText('` + file + `'))"`
	if signs := Scrambled(powershell, line); len(signs) != 0 {
		t.Errorf("a plain loader was called scrambled: %v", signs)
	}
	s := healthy()
	task := through(model.ScheduledTask, `\Tidy\Clean`, line, windows(powershell), script(file))
	task.Account = "SYSTEM"
	s.Startup = append(s.Startup, task)
	if got := outcome(Check(s)); got != "startup-script:low" {
		t.Errorf("the loader task gave %q, want startup-script:low", got)
	}
	// The same line with more on it is still a scramble.
	more := `powershell.exe -Command "iex([IO.File]::ReadAllText('` + file + `')); iex $env:X"`
	if signs := Scrambled(powershell, more); len(signs) == 0 {
		t.Error("a line that runs hidden text after loading a script was let through")
	}
}

// A shell that passes a scrambled command to the tool it starts is not
// flagged beside that tool: the same text would be reported twice.
func TestMessengerIsNotFlaggedTwice(t *testing.T) {
	const child = `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -NoProfile -NonInteractive -Command "$s = $env:LAUNCH_SCRIPT; Invoke-Expression -Command $s"`
	const parent = `C:\Windows\System32\cmd.exe /d /s /c ""C:\Windows\System32\chcp.com" 65001 >nul & "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$s = $env:LAUNCH_SCRIPT; Invoke-Expression -Command $s" > "C:\Users\sam\out.txt" 2>&1"`
	s := healthy()
	s.Processes = append(s.Processes,
		model.Process{PID: 9100, Name: "cmd.exe", File: windows(`C:\Windows\System32\cmd.exe`), Command: parent},
		model.Process{PID: 9101, Parent: 9100, Name: "powershell.exe", File: windows(powershell), Command: child})
	findings := Check(s)
	if got := outcome(findings); got != "running-scrambled-command:medium" {
		t.Fatalf("got %q, want one finding", got)
	}
	if findings[0].Subject != "powershell.exe" {
		t.Errorf("the messenger was flagged in place of the tool: %q", findings[0].Subject)
	}

	// A shell with a scrambled command of its own is still flagged, child or no child.
	s = healthy()
	s.Processes = append(s.Processes,
		model.Process{PID: 9100, Name: "powershell.exe", File: windows(powershell), Command: `powershell.exe -Command "iex $env:FIRST"`},
		model.Process{PID: 9101, Parent: 9100, Name: "powershell.exe", File: windows(powershell), Command: `powershell.exe -Command "iex $env:SECOND_AND_DIFFERENT"`})
	if got := outcome(Check(s)); got != "running-scrambled-command:medium running-scrambled-command:medium" {
		t.Errorf("two different scrambled commands gave %q", got)
	}
}

func TestTold(t *testing.T) {
	for _, test := range []struct{ command, want string }{
		{`"C:\a b\tool.exe"  -x   -y`, "-x -y"},
		{`tool.exe -x`, "-x"},
		{`tool.exe`, ""},
		{``, ""},
	} {
		if got := told(test.command); got != test.want {
			t.Errorf("told(%q) = %q, want %q", test.command, got, test.want)
		}
	}
	if relays("cmd /c tool -x", []string{"-x"}) {
		t.Error("a few shared letters were taken for a relayed command")
	}
}

// With administrator rights a thing that still cannot be read is not said
// to need them.
func TestWithheld(t *testing.T) {
	if got := model.Withheld(false, true); got != "can only be read with administrator rights" {
		t.Errorf("without the rights: %q", got)
	}
	for _, several := range []bool{false, true} {
		got := model.Withheld(true, several)
		if strings.Contains(got, "can only be read with") || !strings.Contains(got, "even with administrator rights") {
			t.Errorf("with the rights: %q", got)
		}
	}
	s := healthy()
	s.Elevated = true
	facts := aboutProcess(s, model.Process{PID: 4000, Name: "LsaIso.exe", CommandHidden: true})
	said := ""
	for _, fact := range facts {
		if fact.Label == "Command" {
			said = fact.Value
		}
	}
	if !strings.HasPrefix(said, "Is protected by Windows") {
		t.Errorf("the hidden command of a look with the rights was worded %q", said)
	}
}
