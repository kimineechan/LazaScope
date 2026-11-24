//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
)

// timelineList prints what happened when, newest first, over the last
// days (7 unless told).
func timelineList(days string, demo bool) error {
	span := 7
	if days != "" {
		n, err := strconv.Atoi(strings.TrimSpace(days))
		if err != nil || n < 1 || n > 90 {
			return fmt.Errorf("say how many days back to go, from 1 to 90, such as: lazascope-cli timeline 30")
		}
		span = n
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
	shown := 0
	for _, row := range b.Timeline.Rows {
		if s.Taken.Sub(row.When) > time.Duration(span)*24*time.Hour {
			continue
		}
		shown++
		mark := " "
		switch row.Level {
		case view.First:
			mark = "!"
		case view.Look:
			mark = "*"
		}
		fmt.Printf("%s %s  %-44s %-16s %s\n", mark, row.Cells[0], cut(row.Cells[1], 44), cut(row.Cells[2], 16), row.Cells[3])
	}
	fmt.Printf("\n%d moments in the last %d days. ! marks what to look at first, * what is worth a look.\n", shown, span)
	return nil
}
