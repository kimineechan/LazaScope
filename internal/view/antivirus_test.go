package view

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

const encodedLine = `powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`

// What the installed antivirus said is shown with the thing it was asked
// about, and a hidden command is shown decoded.
func TestAntivirusAndDecodedCommands(t *testing.T) {
	s := pc()
	s.Engine = "Microsoft Defender Antivirus"
	shell := signed(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "Microsoft Windows")
	fine := model.File{Path: `C:\Users\sam\Scripts\tidy.cmd`, Exists: true, Script: &model.Script{Lines: []string{"@echo off"}}, Opinion: model.Opinion{Asked: true}}
	bad := model.File{Path: `C:\Users\sam\Scripts\odd.ps1`, Exists: true, Script: &model.Script{Lines: []string{"iex $x"}}, Opinion: model.Opinion{Asked: true, Harmful: true, Name: "Trojan:PowerShell/Example.A"}}
	s.Startup = append(s.Startup, entry(model.RunKey, "Tidy", fine), entry(model.RunKey, "Odd", bad),
		model.Startup{Kind: model.RunKey, Name: "Upd", Where: "a made-up place", Command: encodedLine, Program: shell, Target: shell, Enabled: true, Said: model.Opinion{Asked: true, Harmful: true}})
	s.Processes = append(s.Processes, model.Process{PID: 9000, Name: "powershell.exe", File: shell, Command: encodedLine, Said: model.Opinion{Asked: true}})
	book := build(s)

	said := words(find(t, book.Startup, "Tidy").Detail)
	if !strings.Contains(said, "What the antivirus says\nLazaScope handed this script to Microsoft Defender Antivirus and asked. It raised no objection.") ||
		!strings.Contains(said, "It is not a promise that it is harmless.") {
		t.Errorf("a script the antivirus has nothing against:\n%s", said)
	}
	said = words(find(t, book.Startup, "Odd").Detail)
	if !strings.Contains(said, "It calls it harmful, under the name Trojan:PowerShell/Example.A.") || !strings.Contains(said, "That is the antivirus's judgement, not LazaScope's.") {
		t.Errorf("a script the antivirus objects to:\n%s", said)
	}
	if row := find(t, book.Startup, "Odd"); row.Level != First {
		t.Errorf("the row of a script the antivirus objects to is at level %v", row.Level)
	}

	row := find(t, book.Startup, "Upd")
	said = words(row.Detail)
	for _, want := range []string{
		"What the encoded command says", "LazaScope has turned them back into text. Nothing was run.", "IEX (New-Object Net.WebClient)",
		"It runs a piece of text as commands", "LazaScope handed the commands on this line to Microsoft Defender Antivirus and asked. It calls them harmful.",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the detail of a hidden command lacks %q:\n%s", want, said)
		}
	}
	// The decoded lines are marked, so that a saved report leaves them out.
	for _, line := range row.Detail {
		if strings.Contains(line.Text, "New-Object") && line.Style != Excerpt {
			t.Errorf("a decoded line is not marked as copied content: %q", line.Text)
		}
	}

	said = words(find(t, book.Running, "9000").Detail)
	if !strings.Contains(said, "What the encoded command says") || !strings.Contains(said, "and asked. It raised no objection.") {
		t.Errorf("a running hidden command:\n%s", said)
	}

	// With no antivirus named, the sentence still reads.
	s.Engine = ""
	if said := words(find(t, build(s).Startup, "Tidy").Detail); !strings.Contains(said, "LazaScope handed this script to the antivirus on this PC and asked.") {
		t.Errorf("with no antivirus named:\n%s", said)
	}
	// A thing that was never asked about says nothing of the antivirus.
	if said := words(find(t, book.Startup, "Notes").Detail); strings.Contains(said, "antivirus") {
		t.Errorf("a program that was not asked about speaks of the antivirus:\n%s", said)
	}
}
