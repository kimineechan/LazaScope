package cmdline

import "testing"

func TestLoads(t *testing.T) {
	const script = `C:\ProgramData\Tidy\Scripts\tidy.ps1`
	for _, test := range []struct {
		commands string
		file     string
	}{
		// The ways of running one named script, and nothing else.
		{`iex([IO.File]::ReadAllText('` + script + `'))`, script},
		{`Invoke-Expression ([System.IO.File]::ReadAllText("` + script + `"))`, script},
		{`iex ([io.file]::readalltext('` + script + `'));`, script},
		{`Get-Content '` + script + `' -Raw | iex`, script},
		{`gc ` + script + ` | Invoke-Expression`, script},
		{`Get-Content -Path '` + script + `' | iex`, script},
		{`iex (Get-Content '` + script + `' -Raw)`, script},
		{`Invoke-Expression (gc -LiteralPath ` + script + `)`, script},
		{`& '` + script + `'`, script},
		{`& '` + script + `' -Quiet -Days 3`, script},
		{`. '` + script + `'`, script},
		{`& ` + script, script},
		{script, script},
		{`& { iex([IO.File]::ReadAllText('` + script + `')) }`, script},
		{`& 'C:\Users\sam\My Scripts\tidy up.ps1'`, `C:\Users\sam\My Scripts\tidy up.ps1`},

		// Anything more than that is not a plain loader.
		{`iex([IO.File]::ReadAllText('` + script + `')); Remove-Item C:\Logs -Recurse`, ""},
		{`iex ((New-Object Net.WebClient).DownloadString('https://example.com/a.ps1'))`, ""},
		{`iex([IO.File]::ReadAllText($env:TEMP + '\a.ps1'))`, ""},
		{`iex $env:PAYLOAD`, ""},
		{`& '` + script + `'; iex $x`, ""},
		{`& '` + script + `' | Out-Null`, ""},
		{`& '` + script + `' $(whoami)`, ""},
		{`Get-Content '` + script + `' | Select-Object -First 1`, ""},
		{`Start-Process notepad`, ""},
		{``, ""},
	} {
		file, ok := Loads(test.commands)
		if file != test.file || ok != (test.file != "") {
			t.Errorf("Loads(%q) = %q, %v; want %q", test.commands, file, ok, test.file)
		}
	}
}

func TestPowerShellCommand(t *testing.T) {
	for _, test := range []struct{ line, commands string }{
		{`powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iex([IO.File]::ReadAllText('C:\a\b.ps1'))"`, `iex([IO.File]::ReadAllText('C:\a\b.ps1'))`},
		{`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c Write-Host hello`, `Write-Host hello`},
		{`pwsh -NoLogo Get-Date`, `Get-Date`},
		{`powershell -File C:\a\b.ps1`, ``},
		{`powershell -EncodedCommand SQBFAFgA`, ``},
		{`powershell`, ``},
		{`cmd.exe /c powershell -Command Get-Date`, ``}, // not a PowerShell line: cmd is asked first
		{`notepad.exe -Command x`, ``},
	} {
		if got := PowerShellCommand(test.line); got != test.commands {
			t.Errorf("PowerShellCommand(%q) = %q, want %q", test.line, got, test.commands)
		}
	}
}

// A task that makes PowerShell read a named script and run it is followed
// to that script, like one that names the script with -File.
func TestFollowsALoader(t *testing.T) {
	const script = `C:\ProgramData\Tidy\Scripts\tidy.ps1`
	w := pc(script)
	read := w.Launch("powershell.exe", `-ExecutionPolicy Bypass -NoProfile -Command "iex([IO.File]::ReadAllText('`+script+`'))"`)
	if read.Target != script || read.Inline || read.Carrier != Script || !read.Found {
		t.Errorf("the loader was read as %+v", read)
	}
	// Commands that do more stay what they were: commands on the line.
	read = w.Launch("powershell.exe", `-Command "iex([IO.File]::ReadAllText('`+script+`')); Remove-Item C:\Logs"`)
	if read.Target != "" || !read.Inline {
		t.Errorf("a line that does more than load was read as %+v", read)
	}
}
