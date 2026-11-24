//go:build windows

package main

import (
	"fmt"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
)

// printPage takes a look and prints one of the window's pages as a table.
func printPage(pick func(b *view.Book) *view.Page, demo bool) error {
	var s *model.Snapshot
	var findings []rules.Finding
	if demo {
		s = sample.PC()
		findings = rules.Check(s)
	} else {
		s = scan.Run(scan.Everything, progress)
		findings = scan.Judge(s)
	}
	page := pick(view.Build(s, findings))
	fmt.Printf("%s\n%s\n\n", strings.ToUpper(page.Title), page.Intro)
	for _, row := range page.Rows {
		var cells []string
		for i, cell := range row.Cells {
			if i == 0 && cell == "" {
				cell = "-"
			}
			cells = append(cells, cell)
		}
		fmt.Printf("  %s\n", strings.Join(cells, " | "))
	}
	if len(page.Rows) == 0 {
		fmt.Println("  Nothing to show.")
	}
	return nil
}
