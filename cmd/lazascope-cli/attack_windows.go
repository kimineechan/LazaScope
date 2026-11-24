//go:build windows

package main

import (
	"fmt"
	"os"

	"lazascope"
	"lazascope/internal/model"
	"lazascope/internal/report"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
	"lazascope/internal/winpath"
)

// attackLayer writes a layer for MITRE's ATT&CK Navigator: the techniques
// that a look found traces of or, with coverage set, the techniques that
// LazaScope's rules look for.
func attackLayer(path string, coverage, demo bool) error {
	if path == "" {
		return fmt.Errorf("name the file to write, ending in .json")
	}
	if winpath.Ext(path) != ".json" {
		return fmt.Errorf("a layer for the ATT&CK Navigator is a .json file, so the name must end in .json")
	}
	var content []byte
	var count int
	what := "ATT&CK techniques that findings on this PC may be traces of"
	if coverage {
		content, count = report.CoverageLayer(lazascope.Version())
		what = "ATT&CK techniques that LazaScope's rules look for"
	} else {
		var s *model.Snapshot
		if demo {
			s = sample.PC()
			what = "ATT&CK techniques that findings on the made-up PC may be traces of"
		} else {
			s = scan.Run(scan.Everything, progress)
		}
		findings := rules.Check(s)
		if !demo {
			findings = scan.Judge(s)
		}
		content, count = report.NavigatorLayer(view.Build(s, findings), lazascope.Version())
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s: %d %s.\n", path, count, what)
	fmt.Println("To see it, open MITRE's ATT&CK Navigator at https://mitre-attack.github.io/attack-navigator/ in a web browser, choose Open Existing Layer, then Upload from local, and pick the file.")
	if !coverage {
		fmt.Println(report.Careful)
	}
	return nil
}
