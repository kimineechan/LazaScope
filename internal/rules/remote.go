package rules

import (
	"lazascope/internal/i18n"
	"sort"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/winpath"
)

// remoteTool describes one program that lets someone else see or control
// this PC over the internet.
type remoteTool struct {
	name      string
	programs  []string // the names of its running programs, without .exe
	services  []string // the names of its services
	installed []string // words found in its name in the list of installed apps
	builtIn   bool     // it comes with Windows, so only a running copy is worth a mention
}

// The remote-control programs LazaScope knows by name. Every one of them
// is honest software. They are listed because support scams and intruders
// use the same programs, and the owner of a PC should know if one is there.
var remoteTools = []remoteTool{
	{name: "AnyDesk", programs: []string{"anydesk"}, services: []string{"anydesk"}, installed: []string{"anydesk"}},
	{name: "TeamViewer", programs: []string{"teamviewer", "teamviewer_service", "tv_w32", "tv_x64"}, services: []string{"teamviewer"}, installed: []string{"teamviewer"}},
	{name: "RustDesk", programs: []string{"rustdesk"}, services: []string{"rustdesk"}, installed: []string{"rustdesk"}},
	{name: "Chrome Remote Desktop", programs: []string{"remoting_host", "remote_assistance_host", "remoting_desktop"}, services: []string{"chromoting"}, installed: []string{"chrome remote desktop"}},
	{name: "Splashtop", programs: []string{"srservice", "srmanager", "srfeature", "sragent"}, services: []string{"splashtopremoteservice"}, installed: []string{"splashtop"}},
	{name: "LogMeIn", programs: []string{"logmein", "lmiguardiansvc", "logmeinsystray"}, services: []string{"logmein", "lmiguardiansvc"}, installed: []string{"logmein client", "logmein pro", "logmein rescue"}},
	{name: "GoToMyPC", programs: []string{"g2comm", "g2svc", "g2pre", "g2tray"}, services: []string{"gotomypc"}, installed: []string{"gotomypc"}},
	{name: "GoTo Resolve", programs: []string{"gotoresolve", "goto.resolve"}, installed: []string{"goto resolve", "gotoassist"}},
	{name: "ScreenConnect (ConnectWise Control)", programs: []string{"screenconnect.clientservice", "screenconnect.windowsclient"}, services: []string{"screenconnect client"}, installed: []string{"screenconnect", "connectwise control"}},
	{name: "Atera", programs: []string{"ateraagent"}, services: []string{"ateraagent"}, installed: []string{"ateraagent", "atera agent"}},
	{name: "NinjaOne", programs: []string{"ninjarmmagent", "ninjarmmagentpatcher"}, services: []string{"ninjarmmagent"}, installed: []string{"ninjarmm", "ninjaone"}},
	{name: "Parsec", programs: []string{"parsecd", "pservice"}, services: []string{"parsec"}, installed: []string{"parsec"}},
	{name: "Radmin Server", programs: []string{"rserver3"}, services: []string{"rserver3"}, installed: []string{"radmin server"}},
	{name: "Ammyy Admin", programs: []string{"aa_v3", "ammyy_admin"}, services: []string{"ammyyadmin"}, installed: []string{"ammyy"}},
	{name: "Supremo", programs: []string{"supremo", "supremoservice", "supremohelper"}, services: []string{"supremoservice"}, installed: []string{"supremo"}},
	{name: "RemotePC", programs: []string{"remotepcservice", "remotepcdesktop", "rpcsuite"}, services: []string{"rpcservice", "remotepcservice"}, installed: []string{"remotepc"}},
	{name: "Zoho Assist", programs: []string{"zaservice", "za_connect", "zohours"}, services: []string{"zoho assist"}, installed: []string{"zoho assist"}},
	{name: "DWService", programs: []string{"dwagent", "dwagsvc"}, services: []string{"dwagent"}, installed: []string{"dwagent", "dwservice"}},
	{name: "NetSupport", programs: []string{"client32"}, services: []string{"client32"}, installed: []string{"netsupport"}},
	{name: "Remote Utilities", programs: []string{"rutserv", "rfusclient"}, services: []string{"rmanservice"}, installed: []string{"remote utilities"}},
	{name: "AeroAdmin", programs: []string{"aeroadmin"}, services: []string{"aeroadmin"}, installed: []string{"aeroadmin"}},
	{name: "DameWare", programs: []string{"dwrcs", "dwrcst"}, services: []string{"dwmrcs"}, installed: []string{"dameware"}},
	{name: "BeyondTrust Remote Support (Bomgar)", programs: []string{"bomgar-scc", "bomgar-rep", "bomgar-pac"}, installed: []string{"bomgar", "beyondtrust remote support"}},
	{name: "MeshCentral", programs: []string{"meshagent"}, services: []string{"mesh agent"}, installed: []string{"mesh agent", "meshcentral"}},
	{name: "Tactical RMM", programs: []string{"tacticalrmm"}, services: []string{"tacticalrmm"}, installed: []string{"tactical rmm"}},
	{name: "NoMachine", programs: []string{"nxserver", "nxd", "nxnode"}, services: []string{"nxservice"}, installed: []string{"nomachine"}},
	{name: "ISL Online", programs: []string{"isllight", "islalwaysonmonitor"}, services: []string{"isl alwayson"}, installed: []string{"isl light", "isl alwayson"}},
	{name: "Getscreen.me", programs: []string{"getscreen"}, services: []string{"getscreen"}, installed: []string{"getscreen"}},
	{name: "HopToDesk", programs: []string{"hoptodesk"}, services: []string{"hoptodesk"}, installed: []string{"hoptodesk"}},
	{name: "LiteManager", programs: []string{"romserver", "romfusclient"}, services: []string{"romservice"}, installed: []string{"litemanager"}},
	{name: "Iperius Remote", programs: []string{"iperiusremote"}, installed: []string{"iperius remote"}},
	{name: "RealVNC Server", programs: []string{"vncserver", "winvnc4"}, services: []string{"vncserver"}, installed: []string{"vnc server", "realvnc"}},
	{name: "TightVNC Server", programs: []string{"tvnserver"}, services: []string{"tvnserver"}, installed: []string{"tightvnc"}},
	{name: "UltraVNC Server", programs: []string{"winvnc"}, services: []string{"uvnc_service"}, installed: []string{"ultravnc"}},
	{name: "TigerVNC Server", programs: []string{"winvnc4"}, services: []string{"tigervnc"}, installed: []string{"tigervnc"}},
	{name: "OpenSSH server", programs: []string{"sshd"}, services: []string{"sshd"}},
	{name: "Quick Assist", programs: []string{"quickassist"}, builtIn: true},
	{name: "Windows Remote Assistance", programs: []string{"msra"}, builtIn: true},
	{name: "Windows Remote Management", services: []string{"winrm"}, builtIn: true},
}

// RemoteTool is a remote-control program found on the PC.
type RemoteTool struct {
	Name      string
	Running   bool     // it is running now
	Starts    bool     // it is set to start by itself
	Installed bool     // it is in the list of installed apps
	Evidence  []string // where it was seen
}

// RemoteTools looks through the running programs, the services, the
// start-up entries and the list of installed apps for remote-control
// programs it knows by name.
func RemoteTools(s *model.Snapshot) []RemoteTool {
	var found []RemoteTool
	for _, tool := range remoteTools {
		hit := RemoteTool{Name: tool.name}
		seen := map[string]bool{}
		note := func(evidence string) {
			if !seen[evidence] {
				seen[evidence] = true
				hit.Evidence = append(hit.Evidence, evidence)
			}
		}
		for _, p := range s.Processes {
			if matches(tool.programs, winpath.Stem(p.Name)) {
				hit.Running = true
				note("Running: " + p.Name)
			}
			for _, service := range p.Services {
				if matches(tool.services, strings.ToLower(service)) {
					hit.Running = true
					note("Running service: " + service)
				}
			}
		}
		for _, e := range s.Startup {
			if !e.Enabled {
				continue
			}
			byService := e.Kind == model.Service && matches(tool.services, strings.ToLower(e.Name))
			byProgram := e.Kind != model.Service && e.Kind != model.Driver && (matches(tool.programs, winpath.Stem(e.Program.Path)) || matches(tool.programs, winpath.Stem(e.Target.Path)))
			if byService || byProgram {
				if tool.builtIn && !e.Running {
					continue
				}
				hit.Starts = true
				note("Starts by itself: " + e.Kind.String() + " " + e.Shown())
			}
		}
		if !tool.builtIn {
			for _, program := range s.Guard.Programs {
				name := strings.ToLower(program.Name)
				for _, word := range tool.installed {
					if strings.Contains(name, word) {
						hit.Installed = true
						note("Installed: " + program.Name)
						break
					}
				}
			}
		}
		if hit.Running || hit.Starts || hit.Installed {
			found = append(found, hit)
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Running && !found[j].Running })
	return found
}

func matches(names []string, name string) bool {
	if name == "" {
		return false
	}
	for _, have := range names {
		if have == name {
			return true
		}
	}
	return false
}

var accountRules = []Rule{
	{
		ID: "remote-desktop-on", Area: model.Accounts, Severity: Medium, Topic: "rdp",
		Title: i18n.T("Remote Desktop is switched on"),
		Why:   "Remote Desktop lets someone sign in to this PC from another device and use it as if they sat in front of it. It is off by default. When it is on, anyone who can reach the PC and guess or steal a password gets the whole desktop, and it is one of the most attacked doors on the internet.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			if s.Guard.RemoteDesktop != model.Yes {
				return
			}
			f := r.find("Remote Desktop",
				"This PC accepts Remote Desktop connections. Anyone who can reach it over the network and knows an account's password can sign in and use it.",
				"If you do not use it, switch it off under Settings > System > Remote Desktop. If you do, keep it away from the open internet and use strong passwords.",
				Fact{"Remote Desktop", "On"}, Fact{"Asks for a password before showing the sign-in screen", s.Guard.RemoteNLA.String()})
			if s.Guard.RemoteNLA == model.No {
				f.Reason += " It also shows the sign-in screen to anyone who connects, before they have proved who they are, which exposes it to more attacks."
			}
			found = append(found, f)
			return
		},
	},
	{
		ID: "remote-tool", Area: model.Accounts, Severity: Medium,
		Title: i18n.T("Remote-control software is on this PC"),
		Why:   "Programs such as AnyDesk and TeamViewer let someone else see the screen and use the mouse and keyboard from anywhere. That is exactly what they are for, and it is fine if you installed one. They are also the first thing a fake support caller asks a victim to install, and intruders leave them behind as a way back in.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, tool := range RemoteTools(s) {
				state := "is installed"
				switch {
				case tool.Running && tool.Starts:
					state = "is running now and starts by itself"
				case tool.Running:
					state = "is running now"
				case tool.Starts:
					state = "is set to start by itself"
				}
				var facts []Fact
				for _, evidence := range tool.Evidence {
					label, value, _ := strings.Cut(evidence, ": ")
					if value == "" {
						label, value = "Seen", evidence
					}
					facts = append(facts, Fact{label, value})
				}
				r.at(RemoteRef(tool.Name))
				f := r.find(tool.Name,
					tool.Name+" "+state+". It lets another person see or control this PC over the internet. That is fine if you installed it and know who can connect.",
					"If you use it, check its settings for unattended access and set a strong password there. If you did not install it, or someone on the phone talked you into it, uninstall it under Settings > Apps and change your important passwords from another device.", facts...)
				if !tool.Running && !tool.Starts {
					f.Severity = Low
				}
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "guest-on", Area: model.Accounts, Severity: Medium, Topic: "guest",
		Title: i18n.T("The Guest account is switched on"),
		Why:   "Guest is a built-in account with no password. Windows keeps it switched off. Switched on, it lets anyone at the keyboard, and in some set-ups anyone on the network, use the PC without proving who they are.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			if s.Guard.Guest == model.Yes {
				found = append(found, r.find("Guest account",
					"The built-in Guest account is switched on. It has no password, so anyone can sign in with it.",
					"Unless you need it, switch it off: open Computer Management from the Start menu, go to Local Users and Groups > Users, open Guest and tick Account is disabled."))
			}
			return
		},
	},
	{
		ID: "auto-sign-in", Area: model.Accounts, Severity: Medium, Topic: "autosignin",
		Title: i18n.T("Windows signs in by itself"),
		Why:   "Automatic sign-in skips the password when the PC starts. Anyone who switches the PC on gets the account and everything in it. The password is also kept on the PC where programs can read it.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			if s.Guard.AutoSignIn == model.Yes {
				who := "an account"
				if s.Guard.AutoUser != "" {
					who = "the account " + s.Guard.AutoUser
				}
				found = append(found, r.find("Automatic sign-in",
					"Windows signs "+who+" in by itself when the PC starts, with no password asked. Whoever switches the PC on is in.",
					"If the PC never leaves a safe room this may be what you want. To switch it off, press Windows + R, type netplwiz, and tick \"Users must enter a user name and password\"."))
			}
			return
		},
	},
	{
		ID: "builtin-administrator-on", Area: model.Accounts, Severity: Low,
		Title: i18n.T("The built-in Administrator account is switched on"),
		Why:   "Every PC has a hidden account called Administrator that Windows keeps switched off. It has full rights, its name is known to every attacker, and by default Windows does not ask it to confirm anything.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, account := range s.Guard.Admins {
				r.at(AdminRef(account.Name))
				if account.BuiltIn == "Administrator" && account.Disabled == model.No {
					found = append(found, r.find(account.Name,
						"The built-in Administrator account ("+account.Name+") is switched on. Windows normally keeps it off and lets people use their own accounts.",
						"If nobody uses it, switch it off: open Computer Management from the Start menu, go to Local Users and Groups > Users, open the account and tick Account is disabled. Make sure another administrator account works first."))
				}
			}
			return
		},
	},
}
