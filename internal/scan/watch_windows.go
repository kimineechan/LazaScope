//go:build windows

package scan

import (
	"fmt"
	"time"

	"lazascope/internal/compare"
	"lazascope/internal/files"
	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/procs"
)

// Longest is the longest a watch may last.
const Longest = 10 * time.Minute

// Watch takes a look at this PC and then keeps looking for a while: once a
// second it reads which programs are running and which connections are
// open, and adds whatever was not there before. A program that starts,
// sends something and is gone again within seconds is kept in the look,
// where a single look would never have seen it.
//
// It only reads. It installs nothing and listens to no traffic: it sees
// that a connection exists, not what is said over it. A program that lives
// for less than a second can still slip between two readings.
//
// stop, when it is closed, ends the watch early. note is told what is
// being done, for a status line.
func Watch(lasting time.Duration, stop <-chan struct{}, note func(stage string)) *model.Snapshot {
	if note == nil {
		note = func(string) {}
	}
	if lasting > Longest {
		lasting = Longest
	}
	s := Run(Everything, note)
	tracker := compare.Watch(s)
	library := files.Open()
	defer library.Close()
	tracker.Describe = func(p *model.Process) { p.File = library.Look(p.File.Path) }

	began := time.Now()
	second := time.NewTicker(time.Second)
	defer second.Stop()
watching:
	for {
		left := lasting - time.Since(began)
		if left <= 0 {
			break
		}
		select {
		case <-stop:
			break watching
		case <-second.C:
		}
		// A reading that goes wrong is skipped. The next one is a second away.
		func() {
			defer func() { recover() }()
			programs, _ := procs.Collect()
			links, _ := netconn.Collect()
			tracker.Tick(time.Now(), programs, links)
		}()
		c := s.Compared
		note(fmt.Sprintf("Watching: %d seconds left. So far %s and %s.", int(left.Round(time.Second).Seconds()),
			plural(c.NewPrograms, "program has started", "programs have started"), plural(c.NewConnections, "connection was opened", "connections were opened")))
	}
	tracker.Finish(time.Since(began))
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
