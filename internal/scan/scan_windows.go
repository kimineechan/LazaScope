//go:build windows

// Package scan takes one look at this PC: it runs the collectors, then
// finds out who made every file they came across.
package scan

import (
	"fmt"
	"sync"
	"time"

	"lazascope/internal/files"
	"lazascope/internal/model"
	"lazascope/internal/pcinfo"
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
		work.Go(func() { s.Startup, gaps[0] = startup.Collect(world) })
	}
	work.Wait()
	for _, found := range gaps {
		s.Gaps = append(s.Gaps, found...)
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
	s.Took = time.Since(began)
	return s
}
