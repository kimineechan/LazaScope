// Package compare holds one look at a PC against another and says what is
// new, what is gone and which settings differ.
//
// It is used in two ways. A look can be held against a report that was
// saved earlier: "what has changed since last week?". And a look can be
// kept up for a while, so that a program that starts, sends something and
// is gone again within seconds is still seen: a single look would miss it.
//
// The package only compares facts it is handed. It calls nothing.
package compare

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/model"
)

// startupKey names a start-up entry in a way that stays the same from one
// look to the next.
func startupKey(e model.Startup) string {
	if x := e.Extension; x != nil {
		return "extension|" + strings.ToLower(x.Browser+"|"+x.Profile+"|"+x.ID)
	}
	return strings.ToLower(e.Kind.String() + "|" + e.Name + "|" + e.Where)
}

// programKey names a running program by its file, so that the same program
// started twice is one program.
func programKey(p model.Process) string {
	if p.File.Path != "" {
		return strings.ToLower(p.File.Path)
	}
	return "name:" + strings.ToLower(p.Name)
}

// doorKey names a port a program waits on.
func doorKey(c model.Connection) string {
	return strings.ToLower(c.Protocol + "|" + strconv.Itoa(c.LocalPort) + "|" + c.Process)
}

// passing reports whether a waiting port is one of the short-lived ones a
// program opens for a single exchange and drops again. Windows hands those
// out from the top of the range, a different one each time, so one being
// there now and not then says nothing.
func passing(c model.Connection) bool {
	return c.Protocol == "UDP" && c.LocalPort >= 49152
}

// Setting is one protection setting, put into words.
type Setting struct{ Label, Value string }

func answer(a model.Answer, yes, no string) string {
	switch a {
	case model.Yes:
		return yes
	case model.No:
		return no
	}
	return ""
}

// Settings puts the settings worth comparing into words. A setting that
// could not be read has no value, and is then left out of a comparison.
func Settings(g model.Guard) []Setting {
	uac := answer(g.UAC, "on", "off")
	if g.UAC == model.Yes && g.UACSilent == model.Yes {
		uac = "on, but set never to ask"
	}
	disk := ""
	if len(g.Volumes) > 0 {
		disk = answer(g.Volumes[0].Encrypted, "encrypted", "not encrypted")
	}
	list := func(values []string, readable bool) string {
		if !readable {
			return ""
		}
		if len(values) == 0 {
			return "none"
		}
		sort.Strings(values)
		return strings.Join(values, ", ")
	}
	var admins, skips, servers, hosts []string
	for _, a := range g.Admins {
		if a.Disabled != model.Yes {
			admins = append(admins, a.Name)
		}
	}
	for _, e := range g.Exclusions {
		skips = append(skips, e.Value)
	}
	for _, s := range g.NameServers {
		servers = append(servers, s.Address)
	}
	for _, h := range g.Hosts {
		for _, name := range h.Names {
			if !strings.EqualFold(name, "localhost") {
				hosts = append(hosts, name+" to "+h.Address)
			}
		}
	}
	proxy := ""
	if g.Proxy.Read {
		proxy = strings.TrimSpace(g.Proxy.Server + " " + g.Proxy.Script)
		if proxy == "" {
			proxy = "none"
		}
	}
	return []Setting{
		{"Antivirus", answer(g.AntivirusHealth, "good", "needs attention")},
		{"Firewall", answer(g.FirewallHealth, "good", "needs attention")},
		{"Defender real-time protection", answer(g.RealTime, "on", "off")},
		{"Defender tamper protection", answer(g.Tamper, "on", "off")},
		{"Places Defender skips", list(skips, g.ExclusionsVisible)},
		{"User Account Control", uac},
		{"Windows disk", disk},
		{"Secure Boot", answer(g.SecureBoot, "on", "off")},
		{"Remote Desktop", answer(g.RemoteDesktop, "on", "off")},
		{"Guest account", answer(g.Guest, "on", "off")},
		{"Automatic sign-in", answer(g.AutoSignIn, "on", "off")},
		{"Administrator accounts in use", list(admins, g.AdminsVisible)},
		{"Hosts file entries", list(hosts, g.HostsVisible)},
		{"Name servers (DNS)", list(servers, g.NameServersRead)},
		{"Proxy", proxy},
	}
}

// Mark holds a look against an earlier one. Everything in now that then
// did not have is marked as new, and now.Compared says what else differs.
// with finishes the phrase "compared with ...".
func Mark(now, then *model.Snapshot, with string) {
	c := &model.Comparison{With: with, When: then.Taken}
	// A scheduled task that does several things is several entries under
	// one name, so everything of that name is gathered before comparing.
	had := map[string][]model.Startup{}
	for _, e := range then.Startup {
		had[startupKey(e)] = append(had[startupKey(e)], e)
	}
	have := map[string]bool{}
	said := map[string]bool{}
	for i := range now.Startup {
		e := &now.Startup[i]
		key := startupKey(*e)
		have[key] = true
		old, known := had[key]
		if !known {
			e.New = true
			c.NewStartup++
			continue
		}
		sameCommand, sameSwitch := e.Command == "", false
		var before []string
		for _, o := range old {
			sameCommand = sameCommand || o.Command == e.Command || o.Command == ""
			sameSwitch = sameSwitch || o.Enabled == e.Enabled
			if o.Command != "" {
				before = append(before, o.Command)
			}
		}
		switch {
		case !sameCommand:
			c.Changed = append(c.Changed, "What "+e.Shown()+" ("+e.Kind.String()+") runs has changed. It was: "+strings.Join(before, " and ")+". It is now: "+e.Command+".")
		case !sameSwitch && !said[key]:
			said[key] = true
			c.Changed = append(c.Changed, e.Shown()+" ("+e.Kind.String()+") was switched "+onOff(old[0].Enabled)+" and is now switched "+onOff(e.Enabled)+".")
		}
	}
	for _, e := range then.Startup {
		if key := startupKey(e); !have[key] {
			have[key] = true // said once, however many things the entry did
			c.Gone = append(c.Gone, "No longer set to start: "+e.Shown()+" ("+e.Kind.String()+").")
		}
	}

	ran := map[string]bool{}
	for _, p := range then.Processes {
		ran[programKey(p)] = true
	}
	counted := map[string]bool{}
	for i := range now.Processes {
		p := &now.Processes[i]
		if key := programKey(*p); !ran[key] && !p.Self {
			p.New = true
			if !counted[key] {
				counted[key] = true
				c.NewPrograms++
			}
		}
	}

	waited := map[string]bool{}
	for _, d := range then.Connections {
		if d.Listening && !passing(d) {
			waited[doorKey(d)] = true
		}
	}
	waits := map[string]bool{}
	for i := range now.Connections {
		d := &now.Connections[i]
		if !d.Listening || passing(*d) {
			continue
		}
		key := doorKey(*d)
		if !waited[key] {
			d.New = true
			if !waits[key] {
				c.NewDoors++
			}
		}
		waits[key] = true
	}
	for _, d := range then.Connections {
		if key := doorKey(d); d.Listening && !passing(d) && d.Reach != model.ThisPC && !waits[key] {
			waits[key] = true // said once, however many addresses it waited on
			c.Gone = append(c.Gone, "No longer waiting for connections: "+d.Process+" on "+d.Protocol+" port "+strconv.Itoa(d.LocalPort)+".")
		}
	}

	was := map[string]string{}
	for _, setting := range Settings(then.Guard) {
		was[setting.Label] = setting.Value
	}
	for _, setting := range Settings(now.Guard) {
		if before := was[setting.Label]; before != "" && setting.Value != "" && before != setting.Value {
			c.Changed = append(c.Changed, setting.Label+": was "+before+", is now "+setting.Value+".")
		}
	}
	now.Compared = c
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// Tracker keeps a look up over a while. It is handed the running programs
// and the connections again and again, and adds to the look whatever was
// not there before, so that what comes and goes between two looks is kept.
type Tracker struct {
	s        *model.Snapshot
	programs map[string]int // which of s.Processes a running program is
	links    map[string]int // which of s.Connections a connection is

	// Describe, when set, fills in what is known about a new program's file.
	Describe func(p *model.Process)
}

// processKey names one running copy of a program. Windows hands a
// program's number out again once it has ended, so the moment it started
// is part of the name.
func processKey(p model.Process) string {
	return strconv.Itoa(int(p.PID)) + "|" + strconv.FormatInt(p.Started.UnixNano(), 10)
}

func linkKey(c model.Connection) string {
	return c.Protocol + "|" + c.Local + "|" + strconv.Itoa(c.LocalPort) + "|" + c.Remote + "|" + strconv.Itoa(c.RemotePort) + "|" + strconv.Itoa(int(c.PID))
}

// Watch starts a watch from a finished look.
func Watch(s *model.Snapshot) *Tracker {
	t := &Tracker{s: s, programs: map[string]int{}, links: map[string]int{}}
	for i, p := range s.Processes {
		t.programs[processKey(p)] = i
	}
	for i, c := range s.Connections {
		t.links[linkKey(c)] = i
	}
	s.Compared = &model.Comparison{With: "how things stood when the watch began", When: s.Taken, Watched: true}
	return t
}

// Tick takes what is running and connected at one moment of the watch.
func (t *Tracker) Tick(at time.Time, programs []model.Process, links []model.Connection) {
	s, c := t.s, t.s.Compared
	running := map[string]bool{}
	byPID := map[uint32]*model.Process{}
	for i := range programs {
		p := programs[i]
		key := processKey(p)
		running[key] = true
		if _, known := t.programs[key]; !known {
			p.New = true
			if t.Describe != nil {
				t.Describe(&p)
			}
			t.programs[key] = len(s.Processes)
			s.Processes = append(s.Processes, p)
			c.NewPrograms++
		}
	}
	for key, i := range t.programs {
		p := &s.Processes[i]
		if !running[key] && !p.Ended {
			p.Ended, p.Left = true, at
			if p.New {
				c.Ended++
			}
		}
		if !p.Ended {
			byPID[p.PID] = p
		}
	}
	open := map[string]bool{}
	for _, link := range links {
		key := linkKey(link)
		open[key] = true
		if _, known := t.links[key]; known {
			continue
		}
		// A connection Windows is only tidying away was open before the watch
		// could see it, or belongs to a program that has gone.
		if link.State == "Closing" || (link.Listening && passing(link)) {
			continue
		}
		link.New, link.Seen = true, at
		if p := byPID[link.PID]; p != nil {
			link.Process, link.File, link.Services = p.Name, p.File, p.Services
		} else if link.Process == "" {
			link.Process = "A program that has closed"
		}
		t.links[key] = len(s.Connections)
		s.Connections = append(s.Connections, link)
		if link.Listening {
			c.NewDoors++
		} else {
			c.NewConnections++
		}
	}
	for key, i := range t.links {
		if link := &s.Connections[i]; link.New && !open[key] {
			link.Ended = true
		}
	}
}

// Finish ends the watch and notes how long it lasted.
func (t *Tracker) Finish(lasted time.Duration) {
	seconds := int(lasted.Round(time.Second).Seconds())
	t.s.Compared.With = "how things stood when the watch began, " + strconv.Itoa(seconds) + " seconds earlier"
	if seconds == 1 {
		t.s.Compared.With = "how things stood when the watch began, 1 second earlier"
	}
}
