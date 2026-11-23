package report

import (
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sigcheck"
)

// The JSON report carries the facts as they were read, one record per
// start-up entry, running program and connection, so that another tool can
// work with them without reading text meant for people. The shapes are set
// down here, apart from the model, so that the model can change without the
// data format changing with it.

type jsonFile struct {
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
	Program     bool   `json:"program"`               // a Windows program or library, not a script or a document
	Signature   string `json:"signature"`             // signed, unsigned, invalid or unknown
	SignedBy    string `json:"signedBy,omitempty"`    // the name on the certificate
	SignatureIn string `json:"signatureIn,omitempty"` // file or catalogue
	Catalogue   string `json:"catalogue,omitempty"`
	Problem     string `json:"problem,omitempty"`
	Company     string `json:"saysCompany,omitempty"` // what the file says of itself: a claim, not proof
	Description string `json:"saysDescription,omitempty"`
	Version     string `json:"version,omitempty"`
	Original    string `json:"originalName,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Modified    string `json:"modified,omitempty"`
}

type jsonStartup struct {
	Ref         string    `json:"ref"` // what a finding's ref points at
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Title       string    `json:"title,omitempty"`
	RecordedIn  string    `json:"recordedIn"`
	AllUsers    bool      `json:"allUsers"`
	Enabled     bool      `json:"enabled"`
	Running     bool      `json:"running,omitempty"`
	Command     string    `json:"command,omitempty"`
	File        *jsonFile `json:"file,omitempty"`           // the file that does the work
	Through     string    `json:"startedThrough,omitempty"` // the go-between that runs it, such as rundll32
	Subject     string    `json:"subject,omitempty"`
	Account     string    `json:"account,omitempty"`
	Trigger     string    `json:"trigger,omitempty"`
	Description string    `json:"description,omitempty"`
}

type jsonProcess struct {
	Ref           string    `json:"ref"`
	PID           uint32    `json:"pid"`
	Parent        uint32    `json:"parent"`
	ParentGone    bool      `json:"parentGone,omitempty"`
	Name          string    `json:"name"`
	File          *jsonFile `json:"file,omitempty"`
	Command       string    `json:"command,omitempty"`
	CommandHidden bool      `json:"commandHidden,omitempty"`
	User          string    `json:"user,omitempty"`
	Session       uint32    `json:"session"`
	Started       string    `json:"started,omitempty"`
	Services      []string  `json:"services,omitempty"`
	Self          bool      `json:"lazaScopeItself,omitempty"`
}

type jsonConnection struct {
	Protocol   string   `json:"protocol"`
	Listening  bool     `json:"listening"`
	State      string   `json:"state"`
	Local      string   `json:"local"`
	LocalPort  int      `json:"localPort"`
	Remote     string   `json:"remote,omitempty"`
	RemotePort int      `json:"remotePort,omitempty"`
	Reach      string   `json:"reach"`
	PID        uint32   `json:"pid"`
	Process    string   `json:"process"`
	Path       string   `json:"path,omitempty"`
	Services   []string `json:"services,omitempty"`
}

type jsonProduct struct {
	Name     string `json:"name"`
	On       string `json:"on"`
	UpToDate string `json:"upToDate,omitempty"`
}

type jsonNamed struct {
	Name string `json:"name"`
	On   string `json:"on"`
}

type jsonExclusion struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type jsonVolume struct {
	Drive     string `json:"drive"`
	Encrypted string `json:"encrypted"`
	State     string `json:"state,omitempty"`
}

type jsonAccount struct {
	Name     string `json:"name"`
	Group    bool   `json:"group,omitempty"`
	Disabled string `json:"disabled"`
	BuiltIn  string `json:"builtIn,omitempty"`
}

type jsonHosts struct {
	Address string   `json:"address"`
	Names   []string `json:"names"`
}

type jsonInstalled struct {
	Name      string `json:"name"`
	Publisher string `json:"publisher,omitempty"`
	Location  string `json:"location,omitempty"`
}

type jsonProtection struct {
	Antivirus             []jsonProduct   `json:"antivirus"`
	AntivirusVerdict      string          `json:"antivirusVerdict"` // Windows Security's own: yes for good
	FirewallVerdict       string          `json:"firewallVerdict"`
	FirewallProducts      []jsonProduct   `json:"firewallProducts"`
	WindowsFirewall       []jsonNamed     `json:"windowsFirewall"`
	DefenderRealTime      string          `json:"defenderRealTime"`
	DefenderTamper        string          `json:"defenderTamperProtection"`
	DefenderExclusions    []jsonExclusion `json:"defenderExclusions"`
	ExclusionsReadable    bool            `json:"defenderExclusionsReadable"`
	UserAccountControl    string          `json:"userAccountControl"`
	UserAccountNeverAsks  string          `json:"userAccountControlNeverAsks"`
	WindowsBuild          string          `json:"windowsBuild,omitempty"`
	LastUpdate            string          `json:"lastUpdate,omitempty"`
	Volumes               []jsonVolume    `json:"volumes"`
	SecureBoot            string          `json:"secureBoot"`
	RemoteDesktop         string          `json:"remoteDesktop"`
	RemoteDesktopPassword string          `json:"remoteDesktopAsksForPasswordFirst"`
	Administrators        []jsonAccount   `json:"administrators"`
	AdministratorsRead    bool            `json:"administratorsReadable"`
	Guest                 string          `json:"guestAccount"`
	AutoSignIn            string          `json:"automaticSignIn"`
	AutoSignInAs          string          `json:"automaticSignInAs,omitempty"`
	HostsFile             string          `json:"hostsFile,omitempty"`
	Hosts                 []jsonHosts     `json:"hostsEntries"`
	HostsReadable         bool            `json:"hostsReadable"`
	Installed             []jsonInstalled `json:"installedPrograms"`

	// From Microsoft Defender's own log.
	DefenderLogReadable   bool                  `json:"defenderLogReadable"`
	DefenderFound         []jsonDetection       `json:"defenderFound"`
	DefenderLogExclusions []jsonLoggedExclusion `json:"defenderExclusionsInLog"`
	DefenderSwitchedOff   []string              `json:"defenderRealTimeSwitchedOff"`
}

type jsonFacts struct {
	Startup     []jsonStartup    `json:"startup"`
	Processes   []jsonProcess    `json:"processes"`
	Connections []jsonConnection `json:"connections"`
	Protection  jsonProtection   `json:"protection"`
	Health      jsonHealth       `json:"health"`
}

func answer(a model.Answer) string {
	switch a {
	case model.Yes:
		return "yes"
	case model.No:
		return "no"
	}
	return "unknown"
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// file writes a file's facts, or nothing when no file is named.
func file(f model.File) *jsonFile {
	if f.Path == "" {
		return nil
	}
	out := &jsonFile{Path: f.Path, Exists: f.Exists, Program: f.Program, Signature: "unknown",
		SignedBy: f.Signature.Signer, Catalogue: f.Signature.Catalogue, Problem: f.Signature.Problem,
		Company: f.Company, Description: f.Description, Version: f.Version, Original: f.Original, Size: f.Size, Modified: stamp(f.Modified)}
	switch f.Signature.Status {
	case sigcheck.Signed:
		out.Signature = "signed"
	case sigcheck.Unsigned:
		out.Signature = "unsigned"
	case sigcheck.Invalid:
		out.Signature = "invalid"
	}
	switch f.Signature.Source {
	case sigcheck.Embedded:
		out.SignatureIn = "file"
	case sigcheck.Catalogue:
		out.SignatureIn = "catalogue"
	}
	return out
}

func products(list []model.SecurityProduct) []jsonProduct {
	out := []jsonProduct{}
	for _, p := range list {
		out = append(out, jsonProduct{p.Name, answer(p.On), answer(p.UpToDate)})
	}
	return out
}

// facts turns a snapshot into its data form.
func facts(s *model.Snapshot) jsonFacts {
	out := jsonFacts{Startup: []jsonStartup{}, Processes: []jsonProcess{}, Connections: []jsonConnection{}}
	for i, e := range s.Startup {
		entry := jsonStartup{Ref: rules.StartupRef(i), Kind: e.Kind.String(), Name: e.Name, Title: e.Title, RecordedIn: e.Where, AllUsers: e.AllUsers,
			Enabled: e.Enabled, Running: e.Running, Command: e.Command, File: file(e.Works()), Subject: e.Subject, Account: e.Account, Trigger: e.Trigger, Description: e.Description}
		if e.Program.Path != "" && !strings.EqualFold(e.Program.Path, e.Works().Path) {
			entry.Through = e.Program.Path
		}
		out.Startup = append(out.Startup, entry)
	}
	for _, p := range s.Processes {
		out.Processes = append(out.Processes, jsonProcess{Ref: rules.ProcessRef(p.PID), PID: p.PID, Parent: p.Parent, ParentGone: p.ParentGone, Name: p.Name, File: file(p.File),
			Command: p.Command, CommandHidden: p.CommandHidden, User: p.User, Session: p.Session, Started: stamp(p.Started), Services: p.Services, Self: p.Self})
	}
	for _, c := range s.Connections {
		out.Connections = append(out.Connections, jsonConnection{Protocol: c.Protocol, Listening: c.Listening, State: c.State, Local: c.Local, LocalPort: c.LocalPort,
			Remote: c.Remote, RemotePort: c.RemotePort, Reach: c.Reach.String(), PID: c.PID, Process: c.Process, Path: c.File.Path, Services: c.Services})
	}
	g := s.Guard
	p := jsonProtection{
		Antivirus: products(g.Antivirus), AntivirusVerdict: answer(g.AntivirusHealth), FirewallVerdict: answer(g.FirewallHealth), FirewallProducts: products(g.FirewallProducts),
		WindowsFirewall: []jsonNamed{}, DefenderRealTime: answer(g.RealTime), DefenderTamper: answer(g.Tamper), DefenderExclusions: []jsonExclusion{}, ExclusionsReadable: g.ExclusionsVisible,
		UserAccountControl: answer(g.UAC), UserAccountNeverAsks: answer(g.UACSilent), WindowsBuild: g.Build, Volumes: []jsonVolume{}, SecureBoot: answer(g.SecureBoot),
		RemoteDesktop: answer(g.RemoteDesktop), RemoteDesktopPassword: answer(g.RemoteNLA), Administrators: []jsonAccount{}, AdministratorsRead: g.AdminsVisible,
		Guest: answer(g.Guest), AutoSignIn: answer(g.AutoSignIn), AutoSignInAs: g.AutoUser, HostsFile: g.HostsPath, Hosts: []jsonHosts{}, HostsReadable: g.HostsVisible, Installed: []jsonInstalled{},
	}
	if g.UpdateKnown {
		p.LastUpdate = stamp(g.LastUpdate)
	}
	for _, profile := range g.Firewall {
		p.WindowsFirewall = append(p.WindowsFirewall, jsonNamed{profile.Name, answer(profile.On)})
	}
	for _, e := range g.Exclusions {
		p.DefenderExclusions = append(p.DefenderExclusions, jsonExclusion{e.Kind, e.Value})
	}
	for _, v := range g.Volumes {
		p.Volumes = append(p.Volumes, jsonVolume{v.Drive, answer(v.Encrypted), v.State})
	}
	for _, a := range g.Admins {
		p.Administrators = append(p.Administrators, jsonAccount{a.Name, a.Group, answer(a.Disabled), a.BuiltIn})
	}
	for _, h := range g.Hosts {
		p.Hosts = append(p.Hosts, jsonHosts{h.Address, h.Names})
	}
	for _, program := range g.Programs {
		p.Installed = append(p.Installed, jsonInstalled{program.Name, program.Publisher, program.Location})
	}
	history(g, &p)
	out.Protection = p
	out.Health = healthFacts(s.Condition)
	return out
}
