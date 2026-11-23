package report

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"lazascope/internal/model"
)

// Load reads a report that was saved as data (.json) back in, as far as a
// comparison needs it: what was set to start, which programs were running,
// which ports programs waited on, and how the protections stood.
//
// What comes back is not a whole look. It holds no signatures and no
// findings, and must not be judged by the rules or shown as a look. It is
// the "then" to hold a new look against.
func Load(data []byte) (*model.Snapshot, error) {
	var document struct {
		Tool      string     `json:"tool"`
		Generated string     `json:"generated"`
		Computer  string     `json:"computer"`
		User      string     `json:"user"`
		Windows   string     `json:"windows"`
		Facts     *jsonFacts `json:"facts"`
	}
	// A report saved with a mark at its start, as some editors add, is still a report.
	data = []byte(strings.TrimPrefix(string(data), string(rune(0xFEFF))))
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, errors.New("the file is not a report saved as data: it cannot be read as JSON")
	}
	if !strings.HasPrefix(document.Tool, "LazaScope") || document.Facts == nil {
		return nil, errors.New("the file is not a LazaScope report saved as data (the kind whose name ends in .json)")
	}
	taken, err := time.Parse("2006-01-02T15:04:05Z", document.Generated)
	if err != nil {
		return nil, errors.New("the report does not say when it was made")
	}
	s := &model.Snapshot{Taken: taken.Local(), Computer: document.Computer, User: document.User, Windows: document.Windows}
	kinds := map[string]model.StartupKind{}
	for kind := model.RunKey; kind <= model.BrowserExtension; kind++ {
		kinds[kind.String()] = kind
	}
	for _, e := range document.Facts.Startup {
		entry := model.Startup{Kind: kinds[e.Kind], Name: e.Name, Title: e.Title, Where: e.RecordedIn, Command: e.Command, Enabled: e.Enabled}
		if x := e.Extension; x != nil {
			entry.Extension = &model.Extension{Browser: x.Browser, Profile: x.Profile, ID: x.ID, Name: e.Name, Version: x.Version, Enabled: e.Enabled}
		}
		s.Startup = append(s.Startup, entry)
	}
	for _, p := range document.Facts.Processes {
		process := model.Process{PID: p.PID, Name: p.Name, Self: p.Self}
		if p.File != nil {
			process.File.Path = p.File.Path
		}
		s.Processes = append(s.Processes, process)
	}
	for _, c := range document.Facts.Connections {
		reach := model.Internet
		switch c.Reach {
		case model.ThisPC.String():
			reach = model.ThisPC
		case model.LocalNetwork.String():
			reach = model.LocalNetwork
		}
		s.Connections = append(s.Connections, model.Connection{Protocol: c.Protocol, Listening: c.Listening, State: c.State, Local: c.Local, LocalPort: c.LocalPort,
			Remote: c.Remote, RemotePort: c.RemotePort, Reach: reach, PID: c.PID, Process: c.Process})
	}
	said := func(text string) model.Answer {
		switch text {
		case "yes":
			return model.Yes
		case "no":
			return model.No
		}
		return model.NotKnown
	}
	p := document.Facts.Protection
	g := model.Guard{
		AntivirusHealth: said(p.AntivirusVerdict), FirewallHealth: said(p.FirewallVerdict), RealTime: said(p.DefenderRealTime), Tamper: said(p.DefenderTamper),
		ExclusionsVisible: p.ExclusionsReadable, UAC: said(p.UserAccountControl), UACSilent: said(p.UserAccountNeverAsks), SecureBoot: said(p.SecureBoot),
		RemoteDesktop: said(p.RemoteDesktop), Guest: said(p.Guest), AutoSignIn: said(p.AutoSignIn), AdminsVisible: p.AdministratorsRead, HostsVisible: p.HostsReadable,
		NameServersRead: p.NameServersRead, Proxy: model.Proxy{Read: p.ProxyReadable, Server: p.Proxy, Script: p.ProxyScript},
	}
	for _, e := range p.DefenderExclusions {
		g.Exclusions = append(g.Exclusions, model.Exclusion{Kind: e.Kind, Value: e.Value})
	}
	for _, v := range p.Volumes {
		g.Volumes = append(g.Volumes, model.Volume{Drive: v.Drive, Encrypted: said(v.Encrypted), State: v.State})
	}
	for _, a := range p.Administrators {
		g.Admins = append(g.Admins, model.Account{Name: a.Name, Group: a.Group, Disabled: said(a.Disabled), BuiltIn: a.BuiltIn})
	}
	for _, h := range p.Hosts {
		g.Hosts = append(g.Hosts, model.HostsEntry{Address: h.Address, Names: h.Names})
	}
	for _, server := range p.NameServers {
		g.NameServers = append(g.NameServers, model.NameServer{Address: server.Address, Connection: server.Connection, ByHand: server.ByHand})
	}
	s.Guard = g
	return s, nil
}
