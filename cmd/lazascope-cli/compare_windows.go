//go:build windows

package main

import (
	"fmt"
	"lazascope/internal/i18n"
	"os"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/compare"
	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/report"
	"lazascope/internal/scan"
	"lazascope/internal/view"
)

// compareWith takes a look and holds it against a report saved earlier as
// data: what is new, what is gone, and which settings differ.
func compareWith(path string) error {
	if path == "" {
		return fmt.Errorf("%s", i18n.T("name the report to compare with: one saved earlier with a name ending in .json"))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf(i18n.T("the report could not be opened: %v"), err)
	}
	then, err := report.Load(data)
	if err != nil {
		return err
	}
	s := scan.Run(scan.Everything, progress)
	findings := scan.Judge(s)
	compare.Mark(s, then, i18n.T("the report of ")+then.Taken.Format("2 January 2006 at 15:04"))
	book := view.Build(s, findings)
	fmt.Printf("%s\n%s\n", book.Summary, book.Compared)
	if then.Computer != "" && !strings.EqualFold(then.Computer, s.Computer) {
		fmt.Printf("Note: the report is of another PC, %s. Much will show as new for that reason alone.\n", then.Computer)
	}
	listNew(s)
	if len(book.Changes) > 0 {
		fmt.Println("\nChanged or gone:")
		for _, line := range book.Changes {
			fmt.Println("  " + line)
		}
	}
	return nil
}

// watchFor takes a look and keeps it up for a while, then lists what came
// and went.
func watchFor(seconds string) error {
	lasting := 60
	if seconds != "" {
		n, err := strconv.Atoi(seconds)
		if err != nil || n < 1 || n > int(scan.Longest.Seconds()) {
			return fmt.Errorf(i18n.T("say how many seconds to watch for, from 1 to %d"), int(scan.Longest.Seconds()))
		}
		lasting = n
	}
	fmt.Fprintf(os.Stderr, "Watching for %d seconds. Nothing is changed, and no traffic is read: only which programs run and which connections exist.\n", lasting)
	s := scan.Watch(time.Duration(lasting)*time.Second, nil, nil)
	findings := scan.Judge(s)
	book := view.Build(s, findings)
	fmt.Printf("%s\n%s\n", book.Summary, book.Compared)
	listNew(s)
	flagged := 0
	for _, f := range findings {
		for _, p := range s.Processes {
			if p.New && f.Subject == p.Name {
				if flagged == 0 {
					fmt.Println("\nWorth a look among what started:")
				}
				flagged++
				fmt.Printf("  [%s] %s: %s\n", f.Severity, f.Title, f.Subject)
				break
			}
		}
	}
	return nil
}

// listNew prints what a comparison or a watch marked as new.
func listNew(s *model.Snapshot) {
	printed := false
	head := func(title string) {
		if !printed {
			fmt.Println()
		}
		printed = true
		fmt.Println(title)
	}
	first := true
	for _, e := range s.Startup {
		if e.New {
			if first {
				head(i18n.T("New among what starts by itself:"))
				first = false
			}
			fmt.Printf("  %-18s %-40s %s\n", e.Kind, cut(e.Shown(), 40), e.Command)
		}
	}
	first = true
	seen := map[string]bool{}
	for _, p := range s.Processes {
		key := strings.ToLower(p.File.Path + "|" + p.Name)
		if !p.New || seen[key] {
			continue
		}
		seen[key] = true
		if first {
			head(i18n.T("New among what is running:"))
			first = false
		}
		state := "running"
		if p.Ended {
			state = "ended again"
		}
		fmt.Printf("  %-28s %-12s %-34s %s\n", cut(p.Name, 28), state, cut(p.File.Maker(), 34), p.File.Path)
	}
	first = true
	for _, c := range s.Connections {
		if !c.New {
			continue
		}
		if first {
			head(i18n.T("New connections and waiting ports:"))
			first = false
		}
		where := c.Protocol + " port " + strconv.Itoa(c.LocalPort) + " (waiting)"
		if !c.Listening {
			where = netconn.Join(c.Remote, c.RemotePort)
			if len(c.Names) > 0 {
				where = c.Names[0] + " (" + where + ")"
			}
		}
		state := ""
		if c.Ended {
			state = ", closed again"
		}
		fmt.Printf("  %-28s %s%s\n", cut(c.Process, 28), where, state)
	}
	if !printed {
		fmt.Println("\nNothing new.")
	}
}
