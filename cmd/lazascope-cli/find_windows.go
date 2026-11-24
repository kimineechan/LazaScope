//go:build windows

package main

import (
	"fmt"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/query"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
)

// find takes a look and prints the rows of every list that match a search,
// written as in the window's search box. With details set, each row comes
// with the exact evidence that analyst mode shows.
func find(search string, details, demo bool) error {
	if strings.TrimSpace(search) == "" || strings.TrimSpace(search) == "?" {
		fmt.Println(strings.Join(query.Help(), "\n"))
		return nil
	}
	q, err := query.Parse(search)
	if err != nil {
		return err
	}
	var s *model.Snapshot
	var findings []rules.Finding
	if demo {
		s = sample.PC()
		findings = rules.Check(s)
	} else {
		s = scan.Run(scan.Everything, progress)
		findings = scan.Judge(s)
	}
	b := view.Build(s, findings)
	total := 0
	for _, page := range append(b.Pages(), &b.VirusTotal) {
		var found []view.Row
		for _, row := range page.Rows {
			if q.Match(query.Record{Fields: row.Fields, Text: row.Text}) {
				found = append(found, row)
			}
		}
		if len(found) == 0 {
			continue
		}
		fmt.Printf("\n%s (%d)\n", strings.ToUpper(page.Title), len(found))
		for _, row := range found {
			var cells []string
			for _, cell := range row.Cells {
				if cell = strings.TrimSpace(cell); cell != "" {
					cells = append(cells, cell)
				}
			}
			fmt.Printf("  %s\n", strings.Join(cells, " | "))
			if details {
				for _, line := range row.Raw {
					fmt.Printf("      %s\n", line.Text)
				}
			}
		}
		total += len(found)
	}
	fmt.Printf("\n%d rows match.\n", total)
	return nil
}
