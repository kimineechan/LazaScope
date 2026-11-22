//go:build windows

package main

import (
	"fmt"
	"os"

	"lazascope/internal/model"
	"lazascope/internal/scan"
)

func progress(stage string) { fmt.Fprintln(os.Stderr, stage) }

func gaps(s *model.Snapshot, area model.Area) {
	for _, gap := range s.Gaps {
		if gap.Area == area {
			fmt.Println("Could not see:", gap.What)
		}
	}
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// startupList prints everything set to start by itself.
func startupList(details bool) error {
	s := scan.Run(scan.Parts{Startup: true}, progress)
	counts := map[model.StartupKind]int{}
	for _, entry := range s.Startup {
		counts[entry.Kind]++
	}
	fmt.Printf("Starts with Windows: %d entries, read in %d ms\n", len(s.Startup), s.Took.Milliseconds())
	for kind := model.RunKey; kind <= model.LoadedLibrary; kind++ {
		if counts[kind] > 0 {
			fmt.Printf("  %-18s %d\n", kind, counts[kind])
		}
	}
	gaps(s, model.StartsWithWindows)
	fmt.Println()
	fmt.Printf("%-17s %-44s %-3s %-36s %s\n", "KIND", "NAME", "ON", "MAKER", "FILE")
	for _, entry := range s.Startup {
		works := entry.Works()
		fmt.Printf("%-17s %-44s %-3s %-36s %s\n", entry.Kind, cut(entry.Shown(), 44), onOff(entry.Enabled), cut(works.Maker(), 36), works.Path)
		if details {
			fmt.Printf("    where:   %s\n    command: %s\n", entry.Where, entry.Command)
			if entry.Program.Path != works.Path {
				fmt.Printf("    through: %s\n", entry.Program.Path)
			}
			for _, line := range [][2]string{{"when", entry.Trigger}, {"account", entry.Account}, {"about", entry.Description}, {"says", works.Description}} {
				if line[1] != "" {
					fmt.Printf("    %-8s %s\n", line[0]+":", line[1])
				}
			}
			if works.Signature.Problem != "" {
				fmt.Printf("    note:    %s\n", works.Signature.Problem)
			}
		}
	}
	return nil
}
