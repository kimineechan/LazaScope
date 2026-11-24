package virustotal

import (
	"strings"
	"testing"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sigcheck"
)

func file(path string, status sigcheck.Status, signer string) model.File {
	return model.File{Path: path, Exists: true, Program: true, Signature: sigcheck.Result{Status: status, Signer: signer}}
}

// The files worth a lookup are the programs that start or run, flagged
// ones first; never Microsoft's, never LazaScope, never what is switched off.
func TestCandidates(t *testing.T) {
	tool := file(`C:\Program Files\Tool\tool.exe`, sigcheck.Unsigned, "")
	notes := file(`C:\Program Files\Notes\notes.exe`, sigcheck.Signed, "Notes Ltd")
	bent := file(`C:\Program Files\Bent\bent.exe`, sigcheck.Invalid, "Bent Ltd")
	edge := file(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, sigcheck.Signed, "Microsoft Corporation")
	shell := file(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, sigcheck.Signed, "Microsoft Windows")
	self := file(`C:\Users\sam\Downloads\LazaScope.exe`, sigcheck.Unsigned, "")
	off := file(`C:\Program Files\Off\off.exe`, sigcheck.Unsigned, "")
	odd := file(`C:\Users\sam\AppData\Roaming\odd.exe`, sigcheck.Signed, "Odd Ltd")
	script := model.File{Path: `C:\Users\sam\run.cmd`, Exists: true}
	quiet := model.File{Path: `C:\Users\sam\notes.txt`, Exists: true}
	gone := model.File{Path: `C:\Program Files\Gone\gone.exe`}

	s := &model.Snapshot{
		Startup: []model.Startup{
			{Kind: model.RunKey, Name: "Notes", Program: notes, Target: notes, Enabled: true},
			{Kind: model.RunKey, Name: "Tool", Program: tool, Target: tool, Enabled: true},
			{Kind: model.RunKey, Name: "Off", Program: off, Target: off},
			{Kind: model.ScheduledTask, Name: `\Run`, Program: shell, Target: script, Enabled: true},
			{Kind: model.RunKey, Name: "Text", Program: quiet, Target: quiet, Enabled: true},
			{Kind: model.RunKey, Name: "Gone", Program: gone, Target: gone, Enabled: true},
			{Kind: model.BrowserExtension, Name: "Helper", Enabled: true, Extension: &model.Extension{Name: "Helper"}},
		},
		Processes: []model.Process{
			{PID: 1, Name: "tool.exe", File: tool},
			{PID: 2, Name: "msedge.exe", File: edge},
			{PID: 3, Name: "LazaScope.exe", File: self, Self: true},
			{PID: 4, Name: "bent.exe", File: bent},
			{PID: 5, Name: "odd.exe", File: odd},
			{PID: 6, Name: "powershell.exe", File: shell},
		},
	}
	findings := []rules.Finding{
		{Rule: "startup-script", Facts: []rules.Fact{{Label: "File", Value: script.Path}, {Label: "Started through", Value: shell.Path}}},
		{Rule: "running-system-name", Facts: []rules.Fact{{Label: "File", Value: odd.Path}}},
		{Rule: "running-scrambled-command", Facts: []rules.Fact{{Label: "File", Value: shell.Path}}},
	}
	var got []string
	for _, c := range Candidates(s, findings) {
		mark := ""
		if c.Starts {
			mark += "S"
		}
		if c.Runs {
			mark += "R"
		}
		if c.Flagged {
			mark += "!"
		}
		got = append(got, c.Name+":"+mark)
	}
	// Flagged first (by name), then a broken signature, then unsigned, then the rest.
	want := "\\Run:S! | odd.exe:R! | bent.exe:R | Tool:SR | Notes:S"
	if strings.Join(got, " | ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, " | "), want)
	}
}
