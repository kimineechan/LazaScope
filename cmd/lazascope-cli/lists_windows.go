//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"

	"lazascope"
	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/report"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/scan"
	"lazascope/internal/view"
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

// runningList prints the running programs as a family tree.
func runningList(details bool) error {
	s := scan.Run(scan.Parts{Processes: true}, progress)
	fmt.Printf("Running now: %d programs, read in %d ms\n", len(s.Processes), s.Took.Milliseconds())
	gaps(s, model.RunningNow)
	fmt.Println()
	fmt.Printf("%-7s %-7s %-44s %-22s %-32s %s\n", "PID", "PARENT", "NAME", "ACCOUNT", "MAKER", "FILE")
	for _, p := range model.Family(s.Processes) {
		name := strings.Repeat("  ", p.Depth) + p.Name
		maker := p.File.Maker()
		if p.File.Path == "" {
			maker = "Part of Windows itself"
		}
		fmt.Printf("%-7d %-7d %-44s %-22s %-32s %s\n", p.PID, p.Parent, cut(name, 44), cut(p.User, 22), cut(maker, 32), p.File.Path)
		if details {
			command := p.Command
			if p.CommandHidden {
				command = "(needs administrator rights)"
			}
			fmt.Printf("        started: %s  session: %d\n        command: %s\n", p.Started.Format("2006-01-02 15:04:05"), p.Session, command)
			if len(p.Services) > 0 {
				fmt.Printf("        services: %s\n", strings.Join(p.Services, ", "))
			}
		}
	}
	return nil
}

// networkList prints the connections and the waiting ports.
func networkList() error {
	s := scan.Run(scan.Parts{Connections: true}, progress)
	connected, waiting := 0, 0
	for _, c := range s.Connections {
		if c.Listening {
			waiting++
		} else {
			connected++
		}
	}
	fmt.Printf("Internet connections: %d connections and %d waiting ports, read in %d ms\n", connected, waiting, s.Took.Milliseconds())
	gaps(s, model.Connections)
	fmt.Println()
	fmt.Printf("%-4s %-24s %-28s %-28s %-14s %-7s %-26s %s\n", "", "STATE", "LOCAL", "REMOTE", "REACH", "PID", "PROGRAM", "MAKER")
	for _, c := range s.Connections {
		remote := ""
		if !c.Listening {
			remote = netconn.Join(c.Remote, c.RemotePort)
		}
		program := c.Process
		if len(c.Services) > 0 {
			program += " (" + strings.Join(c.Services, ", ") + ")"
		}
		fmt.Printf("%-4s %-24s %-28s %-28s %-14s %-7d %-26s %s\n", c.Protocol, c.State, cut(netconn.Join(c.Local, c.LocalPort), 28), cut(remote, 28), c.Reach, c.PID, cut(program, 26), c.File.Maker())
	}
	return nil
}

// protectionList prints how the PC is protected and who can get into it.
func protectionList() error {
	s := scan.Run(scan.Parts{Guard: true}, progress)
	g := s.Guard
	fmt.Printf("%s, %s, signed in as %s, administrator rights: %s\n\n", s.Computer, s.Windows, s.User, onOff(s.Elevated))
	line := func(name string, value any) { fmt.Printf("%-34s %v\n", name, value) }
	line("Antivirus (Windows' verdict)", good(g.AntivirusHealth))
	for _, p := range g.Antivirus {
		line("  "+p.Name, fmt.Sprintf("on: %s, up to date: %s", p.On, p.UpToDate))
	}
	line("Defender real-time protection", g.RealTime)
	line("Defender tamper protection", g.Tamper)
	if g.ExclusionsVisible {
		line("Defender exclusions", len(g.Exclusions))
		for _, e := range g.Exclusions {
			line("  "+e.Kind, e.Value)
		}
	} else {
		line("Defender exclusions", "not readable")
	}
	line("Firewall (Windows' verdict)", good(g.FirewallHealth))
	for _, p := range g.FirewallProducts {
		line("  "+p.Name, fmt.Sprintf("on: %s", p.On))
	}
	for _, p := range g.Firewall {
		line("  Windows Firewall, "+p.Name, p.On)
	}
	line("User Account Control on", g.UAC)
	line("  lets administrators through unasked", g.UACSilent)
	line("Windows build", g.Build)
	if g.UpdateKnown {
		line("Last update installed", fmt.Sprintf("%s (%d days ago)", g.LastUpdate.Format("2006-01-02"), int(s.Taken.Sub(g.LastUpdate).Hours()/24)))
	} else {
		line("Last update installed", "not known")
	}
	for _, v := range g.Volumes {
		line("Disk "+v.Drive+" encrypted", fmt.Sprintf("%s (%s)", v.Encrypted, v.State))
	}
	line("Secure Boot", g.SecureBoot)
	line("Remote Desktop on", g.RemoteDesktop)
	line("  asks for a password first", g.RemoteNLA)
	line("Signs in by itself", g.AutoSignIn)
	line("Guest account on", g.Guest)
	if g.AdminsVisible {
		line("Administrators", len(g.Admins))
		for _, a := range g.Admins {
			about := "account"
			if a.Group {
				about = "group"
			}
			if a.BuiltIn != "" {
				about += ", built-in " + a.BuiltIn
			}
			if a.Disabled != model.NotKnown {
				about += ", switched off: " + a.Disabled.String()
			}
			line("  "+a.Name, about)
		}
	} else {
		line("Administrators", "not readable")
	}
	line("Hosts file", g.HostsPath)
	for _, h := range g.Hosts {
		line("  "+h.Address, strings.Join(h.Names, " "))
	}
	line("Installed programs", len(g.Programs))
	fmt.Println()
	for _, gap := range s.Gaps {
		fmt.Println("Could not see:", gap.What)
	}
	fmt.Printf("\nRead in %d ms\n", s.Took.Milliseconds())
	return nil
}

func good(a model.Answer) string {
	switch a {
	case model.Yes:
		return "good"
	case model.No:
		return "needs attention"
	}
	return "not known"
}

// scanAll takes a full look at the PC and prints what is worth a look.
func scanAll(details, demo bool) error {
	var s *model.Snapshot
	if demo {
		s = sample.PC()
	} else {
		s = scan.Run(scan.Everything, progress)
	}
	findings := rules.Check(s)
	lights := rules.Lights(s, findings)
	fmt.Printf("%s, %s, signed in as %s, administrator rights: %s\n", s.Computer, s.Windows, s.User, onOff(s.Elevated))
	fmt.Printf("%d start-up entries, %d running programs, %d connections and waiting ports, read in %d ms\n\n", len(s.Startup), len(s.Processes), len(s.Connections), s.Took.Milliseconds())
	for area := model.Protection; area < model.Areas; area++ {
		high, medium, low := rules.Count(findings, area)
		fmt.Printf("  %-28s %-20s look first: %d, worth a look: %d, good to know: %d\n", area, lights[area], high, medium, low)
	}
	fmt.Printf("\nWorth a look: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("\n[%s] %s\n    %s  (%s, rule %s)\n", f.Severity, f.Title, f.Subject, f.Area, f.Rule)
		fmt.Printf("    Why:  %s\n    Do:   %s\n", f.Reason, f.Advice)
		if details {
			for _, fact := range f.Facts {
				fmt.Printf("      %-22s %s\n", fact.Label+":", fact.Value)
			}
		}
	}
	if len(s.Gaps) > 0 {
		fmt.Println("\nWhat could not be seen:")
		for _, gap := range s.Gaps {
			fmt.Printf("  %s: %s\n", gap.Area, gap.What)
		}
	}
	return nil
}

// saveReport takes a full look, or shows the made-up PC, and writes the
// report in the form the file's name asks for.
func saveReport(path string, demo bool) error {
	if path == "" {
		return fmt.Errorf("name the file to write, ending in .html, .txt or .json")
	}
	// The name is checked before the look is taken, not after it.
	if err := report.Fits(path); err != nil {
		return err
	}
	var s *model.Snapshot
	if demo {
		s = sample.PC()
	} else {
		s = scan.Run(scan.Everything, progress)
	}
	book := view.Build(s, rules.Check(s))
	content, err := report.Render(book, lazascope.Version(), path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (%d findings). %s\n", path, len(book.Findings), report.Careful)
	return nil
}

// ruleList prints every rule: what it flags and why it exists. With
// markdown set it prints the table that docs/RULES.md holds.
func ruleList(markdown bool) {
	all := rules.All()
	if markdown {
		fmt.Println("| Rule | Area | Usually | What it flags | Why it matters |")
		fmt.Println("| --- | --- | --- | --- | --- |")
		for _, rule := range all {
			fmt.Printf("| `%s` | %s | %s | %s | %s |\n", rule.ID, rule.Area, rule.Severity, rule.Title, rule.Why)
		}
		return
	}
	fmt.Printf("LazaScope has %d rules.\n", len(all))
	for _, rule := range all {
		fmt.Printf("\n%s  (%s, usually: %s)\n    %s\n    %s\n", rule.ID, rule.Area, strings.ToLower(rule.Severity.String()), rule.Title, rule.Why)
	}
}
