//go:build windows

// Package scan takes one look at this PC: it runs the collectors, ties
// what they found together, then finds out who made every file they came
// across.
package scan

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"lazascope/internal/files"
	"lazascope/internal/health"
	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/pcinfo"
	"lazascope/internal/procs"
	"lazascope/internal/protect"
	"lazascope/internal/rules"
	"lazascope/internal/services"
	"lazascope/internal/startup"
)

// Parts chooses what a look takes in. The window asks for everything; the
// command-line tool can ask for one part.
type Parts struct {
	Startup, Processes, Connections, Guard, Health bool
}

// Everything is a look at all five.
var Everything = Parts{true, true, true, true, true}

// guard runs one collector. A fault inside it must not take the whole look
// down with it: the part it was reading is left empty, which the lights
// show as "could not be read", and a note says why.
func guard(area model.Area, what string, gaps *[]model.Gap, collect func()) {
	defer func() {
		if fault := recover(); fault != nil {
			*gaps = append(*gaps, model.Gap{Area: area, What: fmt.Sprintf("%s could not be read, because of an error inside LazaScope itself (%v). Please report it.", what, fault)})
		}
	}()
	collect()
}

// Run takes a look at this PC. It only reads. note, when given, is told
// what is being done, for a status line.
func Run(parts Parts, note func(stage string)) *model.Snapshot {
	if note == nil {
		note = func(string) {}
	}
	began := time.Now()
	// With LAZASCOPE_TIMING set, each stage says how long the look has taken
	// so far, to find what makes a look slow.
	timing := os.Getenv("LAZASCOPE_TIMING") != ""
	mark := func(stage string) {
		if timing {
			fmt.Fprintf(os.Stderr, "  %6d ms  %s\n", time.Since(began).Milliseconds(), stage)
		}
	}
	s := &model.Snapshot{Taken: began, Folders: pcinfo.Folders(), Elevated: pcinfo.Elevated()}
	s.Computer, s.User, s.Windows = pcinfo.Describe()
	world := pcinfo.World()

	note("Reading what starts with Windows, what is running and what is connected...")
	var gaps [5][]model.Gap
	var work sync.WaitGroup
	if parts.Startup {
		work.Go(func() {
			guard(model.StartsWithWindows, "What starts with Windows", &gaps[1], func() { s.Startup, gaps[1] = startup.Collect(world) })
			mark("start-up read")
		})
	}
	if parts.Processes || parts.Connections {
		// Connections are shown with the program they belong to, so the
		// list of programs is needed for them too.
		work.Go(func() {
			guard(model.RunningNow, "What is running", &gaps[2], func() { s.Processes, gaps[2] = procs.Collect() })
			mark("programs read")
		})
	}
	if parts.Connections {
		work.Go(func() {
			guard(model.Connections, "The internet connections", &gaps[3], func() { s.Connections, gaps[3] = netconn.Collect() })
			mark("connections read")
		})
	}
	if parts.Guard {
		work.Go(func() {
			guard(model.Protection, "The state of the protections", &gaps[0], func() { s.Guard, gaps[0] = protect.Collect() })
			mark("protection read")
		})
	}
	if parts.Health {
		work.Go(func() {
			guard(model.Health, "The health of the PC", &gaps[4], func() { s.Condition, gaps[4] = health.Collect() })
			mark("health read")
		})
	}
	work.Wait()
	for _, found := range gaps {
		s.Gaps = append(s.Gaps, found...)
	}

	// Which services run inside which program.
	inside := map[uint32][]string{}
	if parts.Processes || parts.Connections {
		states, _ := services.List()
		for _, state := range states {
			if state.Running && state.PID != 0 && !state.Driver {
				inside[state.PID] = append(inside[state.PID], state.Name)
			}
		}
	}
	byPID := map[uint32]*model.Process{}
	ownerless := 0
	for i := range s.Processes {
		p := &s.Processes[i]
		sort.Strings(inside[p.PID])
		p.Services = inside[p.PID]
		p.Self = int(p.PID) == os.Getpid()
		byPID[p.PID] = p
		// A program that cannot be asked whose it is can still be placed by
		// the services inside it, which are set to run as a known account.
		if p.User == "" && len(p.Services) > 0 {
			p.User = services.Account(p.Services[0])
		}
		if p.User == "" {
			ownerless++
		}
	}
	if ownerless > 0 && parts.Processes {
		what := fmt.Sprintf("The accounts behind %d running programs", ownerless)
		if ownerless == 1 {
			what = "The account behind 1 running program"
		}
		s.Gaps = append(s.Gaps, model.Gap{Area: model.RunningNow, What: what + " " + model.Withheld(s.Elevated, ownerless != 1) + "."})
	}
	for i := range s.Connections {
		c := &s.Connections[i]
		switch p := byPID[c.PID]; {
		case p != nil:
			c.Process, c.File.Path, c.Services = p.Name, p.File.Path, p.Services
		case c.PID == 0:
			c.Process = "A program that has closed" // Windows is tidying the connection away
		default:
			c.Process = "A program that has closed"
		}
	}

	// Every file named so far is now looked at once: does it exist, what
	// does it say of itself, and who signed it.
	library := files.Open()
	defer library.Close()
	var paths []string
	seen := map[string]bool{}
	want := func(path string) {
		if path != "" && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	for _, entry := range s.Startup {
		want(entry.Program.Path)
		want(entry.Target.Path)
	}
	for _, p := range s.Processes {
		want(p.File.Path)
	}
	note(fmt.Sprintf("Checking who made %d files...", len(paths)))
	queue := make(chan string)
	var checks sync.WaitGroup
	for range 4 {
		checks.Go(func() {
			for path := range queue {
				library.Look(path)
			}
		})
	}
	for _, path := range paths {
		queue <- path
	}
	close(queue)
	checks.Wait()
	mark("files checked")
	for i := range s.Startup {
		s.Startup[i].Program = library.Look(s.Startup[i].Program.Path)
		s.Startup[i].Target = library.Look(s.Startup[i].Target.Path)
	}
	for i := range s.Processes {
		s.Processes[i].File = library.Look(s.Processes[i].File.Path)
	}
	for i := range s.Connections {
		s.Connections[i].File = library.Look(s.Connections[i].File.Path)
	}
	if parts.Startup || parts.Processes {
		note("Asking the antivirus about scripts and hidden commands...")
		// A fault here must not cost the rest of the look.
		func() {
			defer func() {
				if fault := recover(); fault != nil {
					s.Gaps = append(s.Gaps, model.Gap{Area: model.StartsWithWindows, What: fmt.Sprintf("The antivirus could not be asked about scripts, because of an error inside LazaScope itself (%v). Please report it.", fault)})
				}
			}()
			askAntivirus(s)
		}()
		mark("antivirus asked")
	}
	if !parts.Processes {
		s.Processes = nil // they were only gathered to name the connections
	}
	s.Took = time.Since(began)
	return s
}

// Judge runs the rules over a look and works out the fingerprint of every
// file a finding is about, so that the file can be told apart from any
// other and looked up by that number. The files are only read.
func Judge(s *model.Snapshot) []rules.Finding {
	findings := rules.Check(s)
	if s.Fingerprints == nil {
		s.Fingerprints = map[string]string{}
	}
	for _, finding := range findings {
		for _, fact := range finding.Facts {
			if fact.Label != "File" && fact.Label != "Started through" {
				continue
			}
			key := strings.ToLower(fact.Value)
			if _, done := s.Fingerprints[key]; done {
				continue
			}
			info, err := os.Stat(fact.Value)
			if err != nil || info.IsDir() || info.Size() > files.FingerprintLimit {
				continue
			}
			if print, err := files.Fingerprint(fact.Value); err == nil {
				s.Fingerprints[key] = print
			}
		}
	}
	return findings
}
