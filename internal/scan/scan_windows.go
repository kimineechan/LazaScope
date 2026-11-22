//go:build windows

// Package scan takes one look at this PC: it runs the collectors, ties
// what they found together, then finds out who made every file they came
// across.
package scan

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"lazascope/internal/files"
	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/pcinfo"
	"lazascope/internal/procs"
	"lazascope/internal/protect"
	"lazascope/internal/services"
	"lazascope/internal/startup"
)

// Parts chooses what a look takes in. The window asks for everything; the
// command-line tool can ask for one part.
type Parts struct {
	Startup, Processes, Connections, Guard bool
}

// Everything is a look at all four.
var Everything = Parts{true, true, true, true}

// Run takes a look at this PC. It only reads. note, when given, is told
// what is being done, for a status line.
func Run(parts Parts, note func(stage string)) *model.Snapshot {
	if note == nil {
		note = func(string) {}
	}
	began := time.Now()
	s := &model.Snapshot{Taken: began, Folders: pcinfo.Folders(), Elevated: pcinfo.Elevated()}
	s.Computer, s.User, s.Windows = pcinfo.Describe()
	world := pcinfo.World()

	note("Reading what starts with Windows, what is running and what is connected...")
	var gaps [4][]model.Gap
	var work sync.WaitGroup
	if parts.Startup {
		work.Go(func() { s.Startup, gaps[1] = startup.Collect(world) })
	}
	if parts.Processes || parts.Connections {
		// Connections are shown with the program they belong to, so the
		// list of programs is needed for them too.
		work.Go(func() { s.Processes, gaps[2] = procs.Collect() })
	}
	if parts.Connections {
		work.Go(func() { s.Connections, gaps[3] = netconn.Collect() })
	}
	if parts.Guard {
		work.Go(func() { s.Guard, gaps[0] = protect.Collect() })
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
		s.Gaps = append(s.Gaps, model.Gap{Area: model.RunningNow, What: fmt.Sprintf("The account behind %d running programs can only be read with administrator rights.", ownerless)})
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
	if !parts.Processes {
		s.Processes = nil // they were only gathered to name the connections
	}
	s.Took = time.Since(began)
	return s
}
