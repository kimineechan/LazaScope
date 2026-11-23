package compare

import (
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

var then = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func run(name, command string) model.Startup {
	return model.Startup{Kind: model.RunKey, Name: name, Where: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Command: command, Enabled: true}
}

func program(pid uint32, path string) model.Process {
	name := path[strings.LastIndexByte(path, '\\')+1:]
	return model.Process{PID: pid, Name: name, File: model.File{Path: path}, Started: then.Add(-time.Hour)}
}

func door(process string, port int) model.Connection {
	return model.Connection{Protocol: "TCP", Listening: true, Local: "0.0.0.0", LocalPort: port, Reach: model.LocalNetwork, Process: process}
}

func extension(id string) model.Startup {
	return model.Startup{Kind: model.BrowserExtension, Name: "Helper", Where: "Google Chrome, profile Default", Enabled: true,
		Extension: &model.Extension{Browser: "Google Chrome", Profile: "Default", ID: id, Name: "Helper"}}
}

// before is a PC as an earlier report found it.
func before() *model.Snapshot {
	return &model.Snapshot{
		Taken:       then,
		Startup:     []model.Startup{run("Notes", `"C:\Program Files\Notes\notes.exe"`), run("Chat", `C:\Users\sam\AppData\Local\Chat\chat.exe`), run("Old", `C:\Old\old.exe`), extension("aaaa")},
		Processes:   []model.Process{program(100, `C:\Windows\explorer.exe`), program(200, `C:\Program Files\Notes\notes.exe`), {PID: 4, Name: "System"}},
		Connections: []model.Connection{door("System", 445), door("sync.exe", 8384), {Protocol: "TCP", Local: "192.168.1.20", LocalPort: 50000, Remote: "203.0.113.9", RemotePort: 443, Process: "notes.exe"}},
		Guard: model.Guard{AntivirusHealth: model.Yes, FirewallHealth: model.Yes, RealTime: model.Yes, Tamper: model.Yes, ExclusionsVisible: true, UAC: model.Yes, UACSilent: model.No,
			Volumes: []model.Volume{{Drive: "C:", Encrypted: model.Yes}}, SecureBoot: model.Yes, RemoteDesktop: model.No, Guest: model.No, AutoSignIn: model.No,
			Admins: []model.Account{{Name: "sam", Disabled: model.No}, {Name: "Administrator", Disabled: model.Yes}}, AdminsVisible: true, HostsVisible: true,
			NameServers: []model.NameServer{{Address: "192.168.1.1"}}, NameServersRead: true, Proxy: model.Proxy{Read: true}},
	}
}

func TestMark(t *testing.T) {
	now := before()
	now.Taken = then.AddDate(0, 0, 7)
	// A week on: one entry gone, one new, one changed, one switched off, a new extension.
	now.Startup = []model.Startup{run("Notes", `"C:\Program Files\Notes\notes.exe" --tray`), run("Chat", `C:\Users\sam\AppData\Local\Chat\chat.exe`), run("Updater", `C:\Users\sam\AppData\Roaming\upd.exe`), extension("aaaa"), extension("bbbb")}
	now.Startup[1].Enabled = false
	// Two copies of a new program, and one that was running before.
	now.Processes = []model.Process{program(101, `C:\Windows\explorer.exe`), program(300, `C:\Users\sam\AppData\Roaming\upd.exe`), program(301, `C:\Users\sam\AppData\Roaming\UPD.exe`), {PID: 4, Name: "System"}, {PID: 999, Name: "lazascope.exe", File: model.File{Path: `C:\Tools\LazaScope.exe`}, Self: true}}
	// A new waiting port, on two addresses. The old one of sync.exe is gone.
	extra := door("upd.exe", 4444)
	extra.Local = "::"
	// A passing port, of the kind that is different every time, is not news.
	passer := model.Connection{Protocol: "UDP", Listening: true, Local: "0.0.0.0", LocalPort: 59125, Reach: model.LocalNetwork, Process: "chat.exe"}
	now.Connections = []model.Connection{door("System", 445), door("upd.exe", 4444), extra, passer}
	now.Guard.RemoteDesktop, now.Guard.UACSilent = model.Yes, model.Yes
	now.Guard.Admins = append(now.Guard.Admins, model.Account{Name: "helper", Disabled: model.No})
	now.Guard.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `C:\Users\sam\AppData\Roaming`}}
	now.Guard.SecureBoot = model.NotKnown // could not be read this time: not a change

	Mark(now, before(), "the report of 15 November 2026")
	c := now.Compared
	if c == nil || c.With != "the report of 15 November 2026" || !c.When.Equal(then) || c.Watched {
		t.Fatalf("the comparison: %+v", c)
	}
	if c.NewStartup != 2 || c.NewPrograms != 1 || c.NewDoors != 1 {
		t.Errorf("counted %d new start-up entries, %d new programs, %d new waiting ports; want 2, 1, 1", c.NewStartup, c.NewPrograms, c.NewDoors)
	}
	marked := ""
	for _, e := range now.Startup {
		if e.New {
			marked += e.Name + "/" + func() string {
				if e.Extension != nil {
					return e.Extension.ID
				}
				return ""
			}() + " "
		}
	}
	if marked != "Updater/ Helper/bbbb " {
		t.Errorf("the start-up entries marked new: %q", marked)
	}
	if now.Processes[0].New || !now.Processes[1].New || !now.Processes[2].New || now.Processes[3].New || now.Processes[4].New {
		t.Errorf("the programs marked new: %+v", now.Processes)
	}
	if now.Connections[0].New || !now.Connections[1].New || !now.Connections[2].New || now.Connections[3].New {
		t.Error("the waiting ports are marked wrongly")
	}
	gone := strings.Join(c.Gone, "\n")
	if len(c.Gone) != 2 || !strings.Contains(gone, "No longer set to start: Old (Registry Run).") || !strings.Contains(gone, "No longer waiting for connections: sync.exe on TCP port 8384.") {
		t.Errorf("gone:\n%s", gone)
	}
	changed := strings.Join(c.Changed, "\n")
	for _, want := range []string{
		`What Notes (Registry Run) runs has changed. It was: "C:\Program Files\Notes\notes.exe". It is now: "C:\Program Files\Notes\notes.exe" --tray.`,
		"Chat (Registry Run) was switched on and is now switched off.",
		"User Account Control: was on, is now on, but set never to ask.",
		"Remote Desktop: was off, is now on.",
		"Administrator accounts in use: was sam, is now helper, sam.",
		`Places Defender skips: was none, is now C:\Users\sam\AppData\Roaming.`,
	} {
		if !strings.Contains(changed, want) {
			t.Errorf("the changes lack %q:\n%s", want, changed)
		}
	}
	if len(c.Changed) != 6 || strings.Contains(changed, "Secure Boot") {
		t.Errorf("%d changes, want 6, and none for a setting that could not be read:\n%s", len(c.Changed), changed)
	}

	// A PC held against itself shows nothing, also when one task does two
	// things and so is listed twice under one name.
	twice := func() *model.Snapshot {
		s := before()
		for _, command := range []string{"first.exe", "second.exe"} {
			s.Startup = append(s.Startup, model.Startup{Kind: model.ScheduledTask, Name: "\\Tidy", Where: "Task Scheduler", Command: command, Enabled: true})
		}
		return s
	}
	same := twice()
	Mark(same, twice(), "itself")
	if c := same.Compared; c.NewStartup+c.NewPrograms+c.NewDoors+len(c.Gone)+len(c.Changed) != 0 {
		t.Errorf("a PC compared with itself: %+v", c)
	}
}

func TestSettings(t *testing.T) {
	labels := map[string]bool{}
	for _, setting := range Settings(before().Guard) {
		if setting.Label == "" || labels[setting.Label] {
			t.Errorf("the setting %q is nameless or named twice", setting.Label)
		}
		labels[setting.Label] = true
		if setting.Value == "" {
			t.Errorf("%s has no value on a PC where everything was read", setting.Label)
		}
	}
	// Nothing read: nothing to compare.
	for _, setting := range Settings(model.Guard{}) {
		if setting.Value != "" {
			t.Errorf("%s has the value %q on a PC where nothing was read", setting.Label, setting.Value)
		}
	}
}

func TestWatch(t *testing.T) {
	s := before()
	began := s.Taken
	tracker := Watch(s)
	described := 0
	tracker.Describe = func(p *model.Process) { described++; p.File.Exists = true }
	base := func() ([]model.Process, []model.Connection) {
		b := before()
		return b.Processes, b.Connections
	}

	// One second in: nothing has changed.
	programs, links := base()
	tracker.Tick(began.Add(time.Second), programs, links)
	if c := s.Compared; c.NewPrograms+c.NewConnections+c.NewDoors+c.Ended != 0 || len(s.Processes) != 3 || len(s.Connections) != 3 {
		t.Fatalf("a quiet second changed something: %+v", c)
	}

	// Two seconds in: a program starts and opens two connections and a port.
	// A connection Windows is only tidying away turns up as well.
	stealer := model.Process{PID: 7000, Name: "invoice.exe", File: model.File{Path: `C:\Users\sam\Downloads\invoice.exe`}, Started: began.Add(1500 * time.Millisecond)}
	out := func(port int, remote string) model.Connection {
		return model.Connection{Protocol: "TCP", State: "Connected", Local: "192.168.1.20", LocalPort: port, Remote: remote, RemotePort: 443, Reach: model.Internet, PID: 7000}
	}
	programs, links = base()
	programs = append(programs, stealer)
	waiting := door("", 9999)
	waiting.PID = 7000
	closing := out(51000, "203.0.113.200")
	closing.State, closing.PID = "Closing", 0
	passer := model.Connection{Protocol: "UDP", Listening: true, Local: "0.0.0.0", LocalPort: 61000, Reach: model.LocalNetwork, PID: 7000}
	links = append(links, out(50001, "198.51.100.7"), out(50002, "198.51.100.7"), waiting, closing, passer)
	tracker.Tick(began.Add(2*time.Second), programs, links)
	if c := s.Compared; c.NewPrograms != 1 || c.NewConnections != 2 || c.NewDoors != 1 || c.Ended != 0 || described != 1 {
		t.Fatalf("after the program started: %+v, described %d", c, described)
	}
	added := s.Processes[len(s.Processes)-1]
	if !added.New || added.Ended || added.Name != "invoice.exe" || !added.File.Exists {
		t.Errorf("the new program: %+v", added)
	}
	link := s.Connections[3]
	if !link.New || link.Ended || link.Process != "invoice.exe" || link.File.Path != stealer.File.Path || !link.Seen.Equal(began.Add(2*time.Second)) {
		t.Errorf("its first connection: %+v", link)
	}
	if len(s.Connections) != 6 {
		t.Errorf("%d connections, want 6: the one being tidied away is not counted as new", len(s.Connections))
	}

	// Three seconds in: the same again. Nothing is counted twice.
	tracker.Tick(began.Add(3*time.Second), programs, links)
	if c := s.Compared; c.NewPrograms != 1 || c.NewConnections != 2 || len(s.Processes) != 4 {
		t.Errorf("seen a second time, it was counted again: %+v", c)
	}

	// Four seconds in: it has sent what it wanted and is gone. So is Notes,
	// which was running before the watch.
	programs, links = base()
	programs = programs[:1+copy(programs[1:], programs[2:])]
	tracker.Tick(began.Add(4*time.Second), programs, links)
	c := s.Compared
	if c.NewPrograms != 1 || c.Ended != 1 {
		t.Errorf("after the program ended: %+v", c)
	}
	added = s.Processes[len(s.Processes)-1]
	if !added.New || !added.Ended || !added.Left.Equal(began.Add(4*time.Second)) {
		t.Errorf("the program that came and went: %+v", added)
	}
	if notes := s.Processes[1]; notes.New || !notes.Ended {
		t.Errorf("a program from before the watch that closed during it: %+v", notes)
	}
	if !s.Connections[3].Ended || !s.Connections[4].Ended || !s.Connections[5].Ended || s.Connections[0].Ended {
		t.Error("the connections that closed are not marked, or one that stayed is")
	}

	// A new program that takes the number of one that ended is a new program.
	reused := model.Process{PID: 7000, Name: "calc.exe", File: model.File{Path: `C:\Windows\System32\calc.exe`}, Started: began.Add(4500 * time.Millisecond)}
	tracker.Tick(began.Add(5*time.Second), append(programs, reused), links)
	if c.NewPrograms != 2 || len(s.Processes) != 5 {
		t.Errorf("a number handed out again: %+v", c)
	}

	tracker.Finish(5 * time.Second)
	if !c.Watched || c.With != "how things stood when the watch began, 5 seconds earlier" {
		t.Errorf("the watch is described as %q", c.With)
	}
}
