package cmdline

import (
	"strings"
	"testing"
)

// pc is a made-up PC: these files exist and nothing else does.
func pc(files ...string) World {
	have := map[string]bool{}
	for _, file := range append(files,
		`C:\Windows\System32\rundll32.exe`, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\regsvr32.exe`,
		`C:\Windows\System32\wscript.exe`, `C:\Windows\System32\mshta.exe`, `C:\Windows\System32\msiexec.exe`,
		`C:\Windows\System32\conhost.exe`, `C:\Windows\System32\shell32.dll`, `C:\Windows\explorer.exe`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\svchost.exe`) {
		have[strings.ToLower(file)] = true
	}
	return World{
		Expand: func(text string) string {
			return strings.NewReplacer("%SystemRoot%", `C:\Windows`, "%windir%", `C:\Windows`, "%ProgramFiles%", `C:\Program Files`,
				"%LOCALAPPDATA%", `C:\Users\sam\AppData\Local`).Replace(text)
		},
		IsFile:  func(path string) bool { return have[strings.ToLower(path)] },
		Windows: `C:\Windows`,
		Search:  []string{`C:\Windows\System32`, `C:\Windows`, `C:\Windows\System32\WindowsPowerShell\v1.0`},
		AppPath: func(name string) string {
			if strings.EqualFold(name, "chrome.exe") {
				return `C:\Program Files\Google\Chrome\Application\chrome.exe`
			}
			return ""
		},
	}
}

func TestRead(t *testing.T) {
	w := pc(
		`C:\Program Files\App\app.exe`, `C:\Program Files\Thing\thing.dll`, `C:\Users\sam\My Tools\run.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Scripts\start.vbs`, `C:\Scripts\job.ps1`,
		`C:\Users\sam\AppData\Local\Tool\tool.exe`, `C:\Program.exe`, `C:\Apps\setup.msi`, `C:\Apps\tool.jar`,
		`C:\Program Files\Java\bin\javaw.exe`, `C:\Scripts\page.hta`, `C:\Tools\helper.bat`,
	)
	for _, test := range []struct {
		command         string
		program, target string
		arguments       string
		found, inline   bool
		carrier         Carrier
	}{
		// A quoted program, with something for it to do.
		{command: `"C:\Program Files\App\app.exe" --minimised`, program: `C:\Program Files\App\app.exe`, arguments: "--minimised", found: true},
		// Not quoted, with a space in the path and nothing after it.
		{command: `C:\Users\sam\My Tools\run.exe`, program: `C:\Users\sam\My Tools\run.exe`, found: true},
		// Not quoted, with a space in the path and a switch after it. C:\Program.exe
		// exists here, and Windows would run it: the first cut that is a program wins.
		{command: `C:\Program Files\App\app.exe /start`, program: `C:\Program.exe`, arguments: `Files\App\app.exe /start`, found: true},
		// Names such as %windir% are filled in first.
		{command: `%windir%\system32\rundll32.exe`, program: `C:\Windows\system32\rundll32.exe`, found: true, carrier: Library},
		{command: `%LOCALAPPDATA%\Tool\tool.exe -quiet`, program: `C:\Users\sam\AppData\Local\Tool\tool.exe`, arguments: "-quiet", found: true},
		// A bare name is looked for where Windows looks.
		{command: `explorer.exe`, program: `C:\Windows\explorer.exe`, found: true},
		{command: `cmd`, program: `C:\Windows\System32\cmd.exe`, found: true, carrier: Script},
		{command: `chrome --no-startup-window`, program: `C:\Program Files\Google\Chrome\Application\chrome.exe`, arguments: "--no-startup-window", found: true},
		// Nothing on disk: the first word is taken as the program, and it is not found.
		{command: `C:\Gone\old.exe /tray`, program: `C:\Gone\old.exe`, arguments: "/tray"},
		{command: `"C:\Gone Away\old.exe" /tray`, program: `C:\Gone Away\old.exe`, arguments: "/tray"},

		// rundll32 is handed a library.
		{command: `rundll32.exe "C:\Program Files\Thing\thing.dll",Start now`, program: `C:\Windows\System32\rundll32.exe`, arguments: `"C:\Program Files\Thing\thing.dll",Start now`,
			target: `C:\Program Files\Thing\thing.dll`, found: true, carrier: Library},
		{command: `C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL`, program: `C:\Windows\System32\rundll32.exe`, arguments: `shell32.dll,Control_RunDLL`,
			target: `C:\Windows\System32\shell32.dll`, found: true, carrier: Library},
		{command: `rundll32.exe /d shell32.dll,Control_RunDLL`, program: `C:\Windows\System32\rundll32.exe`, arguments: `/d shell32.dll,Control_RunDLL`,
			target: `C:\Windows\System32\shell32.dll`, found: true, carrier: Library},
		{command: `rundll32.exe -sta {11111111-2222-3333-4444-555555555555}`, program: `C:\Windows\System32\rundll32.exe`, arguments: `-sta {11111111-2222-3333-4444-555555555555}`,
			found: true, carrier: Library},
		{command: `rundll32 C:\Gone\bad.dll,Entry`, program: `C:\Windows\System32\rundll32.exe`, arguments: `C:\Gone\bad.dll,Entry`, target: `C:\Gone\bad.dll`, found: true, carrier: Library},
		{command: `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`, program: `C:\Windows\System32\rundll32.exe`,
			arguments: `javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`, found: true, carrier: Script, inline: true},
		{command: `regsvr32 /s /n "C:\Program Files\Thing\thing.dll"`, program: `C:\Windows\System32\regsvr32.exe`, arguments: `/s /n "C:\Program Files\Thing\thing.dll"`,
			target: `C:\Program Files\Thing\thing.dll`, found: true, carrier: Library},

		// Script hosts are handed a script, or commands on the line.
		{command: `wscript.exe //B //Nologo "C:\Scripts\start.vbs" one`, program: `C:\Windows\System32\wscript.exe`, arguments: `//B //Nologo "C:\Scripts\start.vbs" one`,
			target: `C:\Scripts\start.vbs`, found: true, carrier: Script},
		{command: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\job.ps1" -Mode fast`, program: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			arguments: `-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\job.ps1" -Mode fast`, target: `C:\Scripts\job.ps1`, found: true, carrier: Script},
		{command: `powershell -w hidden -ep bypass C:\Scripts\job.ps1`, program: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			arguments: `-w hidden -ep bypass C:\Scripts\job.ps1`, target: `C:\Scripts\job.ps1`, found: true, carrier: Script},
		{command: `powershell -nop -w hidden -enc SQBFAFgA`, program: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			arguments: `-nop -w hidden -enc SQBFAFgA`, found: true, carrier: Script, inline: true},
		{command: `powershell -Command "Get-Date"`, program: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, arguments: `-Command "Get-Date"`, found: true, carrier: Script, inline: true},
		{command: `powershell Get-Date`, program: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, arguments: `Get-Date`, found: true, carrier: Script, inline: true},
		{command: `mshta.exe C:\Scripts\page.hta`, program: `C:\Windows\System32\mshta.exe`, arguments: `C:\Scripts\page.hta`, target: `C:\Scripts\page.hta`, found: true, carrier: Script},
		{command: `mshta vbscript:Execute("x")`, program: `C:\Windows\System32\mshta.exe`, arguments: `vbscript:Execute("x")`, found: true, carrier: Script, inline: true},

		// cmd is followed to what it starts.
		{command: `cmd.exe /c start "" "C:\Program Files\App\app.exe" -x`, program: `C:\Windows\System32\cmd.exe`, arguments: `/c start "" "C:\Program Files\App\app.exe" -x`,
			target: `C:\Program Files\App\app.exe`, found: true, carrier: Script},
		{command: `cmd /c start /min C:\Tools\helper.bat`, program: `C:\Windows\System32\cmd.exe`, arguments: `/c start /min C:\Tools\helper.bat`,
			target: `C:\Tools\helper.bat`, found: true, carrier: Script},
		{command: `cmd /c ""C:\Program Files\App\app.exe" -x"`, program: `C:\Windows\System32\cmd.exe`, arguments: `/c ""C:\Program Files\App\app.exe" -x"`,
			target: `C:\Program Files\App\app.exe`, found: true, carrier: Script},
		{command: `cmd /c echo hello > C:\out.txt`, program: `C:\Windows\System32\cmd.exe`, arguments: `/c echo hello > C:\out.txt`, found: true, carrier: Script, inline: true},
		{command: `cmd /c powershell -enc AAAA`, program: `C:\Windows\System32\cmd.exe`, arguments: `/c powershell -enc AAAA`,
			target: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, found: true, carrier: Script, inline: true},
		{command: `conhost.exe --headless powershell -File C:\Scripts\job.ps1`, program: `C:\Windows\System32\conhost.exe`, arguments: `--headless powershell -File C:\Scripts\job.ps1`,
			target: `C:\Scripts\job.ps1`, found: true, carrier: Script},

		// Packages.
		{command: `msiexec /i "C:\Apps\setup.msi" /qn`, program: `C:\Windows\System32\msiexec.exe`, arguments: `/i "C:\Apps\setup.msi" /qn`, target: `C:\Apps\setup.msi`, found: true, carrier: Package},
		{command: `"C:\Program Files\Java\bin\javaw.exe" -Xmx1g -jar C:\Apps\tool.jar`, program: `C:\Program Files\Java\bin\javaw.exe`, arguments: `-Xmx1g -jar C:\Apps\tool.jar`,
			target: `C:\Apps\tool.jar`, found: true, carrier: Package},

		// A batch file named directly is the thing that runs.
		{command: `C:\Tools\helper.bat`, program: `C:\Tools\helper.bat`, found: true},
		{command: ``},
		{command: `   `},
	} {
		got := w.Read(test.command)
		want := Command{Program: test.program, Arguments: test.arguments, Found: test.found, Carrier: test.carrier, Target: test.target, Inline: test.inline}
		if got != want {
			t.Errorf("Read(%s)\n   got %+v\n  want %+v", test.command, got, want)
		}
	}
}

func TestTidy(t *testing.T) {
	w := pc()
	for path, want := range map[string]string{
		`\SystemRoot\System32\drivers\disk.sys`: `C:\Windows\System32\drivers\disk.sys`,
		`\??\C:\Program Files\Thing\thing.sys`:  `C:\Program Files\Thing\thing.sys`,
		`System32\drivers\acpi.sys`:             `C:\Windows\System32\drivers\acpi.sys`,
		`SysWOW64\thing.dll`:                    `C:\Windows\SysWOW64\thing.dll`,
		`"C:\Program Files\App\app.exe"`:        `C:\Program Files\App\app.exe`,
		`%SystemRoot%\system32\svchost.exe`:     `C:\Windows\system32\svchost.exe`,
		`C:/Program Files/App/app.exe`:          `C:\Program Files\App\app.exe`,
		``:                                      ``,
	} {
		if got := w.Tidy(path); got != want {
			t.Errorf("Tidy(%q) = %q, want %q", path, got, want)
		}
	}
}

// A scheduled task keeps the program and what it is told apart.
func TestLaunch(t *testing.T) {
	w := pc(`C:\Program Files\App\app.exe`, `C:\Program Files\Thing\thing.dll`)
	got := w.Launch(`"%ProgramFiles%\App\app.exe"`, ` /update `)
	if want := (Command{Program: `C:\Program Files\App\app.exe`, Arguments: "/update", Found: true}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	got = w.Launch(`%windir%\system32\rundll32.exe`, `"%ProgramFiles%\Thing\thing.dll",Run`)
	if got.Target != `C:\Program Files\Thing\thing.dll` || got.Works() != got.Target || got.Carrier != Library {
		t.Errorf("a task that uses rundll32: got %+v", got)
	}
	if got := w.Launch(`C:\Gone\old.exe`, ""); got.Found || got.Works() != `C:\Gone\old.exe` {
		t.Errorf("a program that is gone: got %+v", got)
	}
}

// cmd carries out words such as echo itself. A program that happens to
// have the same name, as the echo.exe of some developer tools does, is not
// what runs, and must not be reported as the file doing the work.
func TestCmdBuiltIns(t *testing.T) {
	w := pc(`C:\Tools\bin\echo.exe`, `C:\Tools\bin\set.exe`, `C:\Tools\bin\tool.exe`)
	w.Search = append(w.Search, `C:\Tools\bin`)
	for _, command := range []string{`cmd /c echo hello`, `cmd.exe /c echo %COMSPEC:~0,1%`, `cmd /c @echo off`, `cmd /c echo.`, `cmd /c set X=1`, `cmd /c (echo a)`, `cmd /k title Work`} {
		got := w.Read(command)
		if got.Target != "" || !got.Inline || got.Works() != `C:\Windows\System32\cmd.exe` {
			t.Errorf("%s: got %+v, want cmd itself doing the work", command, got)
		}
	}
	// A real program of another name is still followed.
	if got := w.Read(`cmd /c tool --run`); got.Target != `C:\Tools\bin\tool.exe` || got.Inline {
		t.Errorf("a program started through cmd: got %+v", got)
	}
	for word, want := range map[string]bool{"echo hi": true, "ECHO.": true, "@echo off": true, "rem note": true, "echoes": false, "tool": false, "": false, "setx X 1": false} {
		if got := builtIn(word); got != want {
			t.Errorf("builtIn(%q) = %v, want %v", word, got, want)
		}
	}
}

func TestWords(t *testing.T) {
	got := Words(`-a  "two words" c:\x\y.exe ""  "tail`)
	want := []string{"-a", "two words", `c:\x\y.exe`, "", "tail"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	if len(Words("   ")) != 0 {
		t.Error("spaces alone hold no words")
	}
}

// A World with nothing in it must not crash, whatever it is given.
func TestEmptyWorld(t *testing.T) {
	var w World
	for _, command := range []string{`"`, `""`, `" `, `a b c`, `cmd /c`, `cmd /c start`, `cmd /c start ""`, `rundll32`, `rundll32 "`, `powershell -file`, `msiexec /i`, `\??\`, `conhost --headless`} {
		w.Read(command)
	}
}
