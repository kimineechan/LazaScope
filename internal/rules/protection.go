package rules

import (
	"lazascope/internal/i18n"
	"net/netip"
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/winpath"
)

const openSecurity = "Open Windows Security from the Start menu to see and change this. "

// defenderInUse reports whether Microsoft Defender is the antivirus doing
// the work. With another antivirus installed, Defender steps aside, and
// its own switches say nothing about how the PC is protected.
func defenderInUse(g model.Guard) bool {
	others := false
	for _, product := range g.Antivirus {
		if strings.Contains(strings.ToLower(product.Name), "defender") {
			if product.On == model.Yes {
				return true
			}
		} else if product.On == model.Yes {
			others = true
		}
	}
	return !others
}

// The update and security sites that malware blocks in the hosts file to
// stop a PC from being cleaned.
var guardedSites = strings.Fields(`microsoft.com windowsupdate.com windows.com live.com office.com msftncsi.com
	kaspersky avast avg.com bitdefender malwarebytes eset.com norton symantec mcafee sophos trendmicro
	f-secure avira virustotal drweb emsisoft comodo pandasecurity webroot`)

func guarded(name string) bool {
	name = strings.ToLower(name)
	for _, site := range guardedSites {
		if name == site || strings.HasSuffix(name, "."+site) || (!strings.Contains(site, ".") && strings.Contains(name, site)) {
			return true
		}
	}
	return false
}

// nowhere reports whether an address leads nowhere: a hosts line that
// points a name at this PC itself, which is how a site is blocked.
func nowhere(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && (ip.Unmap().IsLoopback() || ip.IsUnspecified())
}

// homeName reports whether a hosts name is the PC's own or a local
// shortcut: no dots, or one of the endings used only inside a network.
func homeName(name string) bool {
	name = strings.ToLower(name)
	for _, ending := range []string{".local", ".localhost", ".internal", ".lan", ".home", ".test", ".example", ".invalid", ".localdomain", ".home.arpa"} {
		if strings.HasSuffix(name, ending) {
			return true
		}
	}
	return !strings.Contains(name, ".") || name == "localhost"
}

var protectionRules = []Rule{
	{
		ID: "antivirus-off", Area: model.Protection, Severity: High, Topic: "antivirus",
		Title: i18n.T("Antivirus protection is off"),
		Why:   i18n.T("Antivirus checks every file as it is opened. Malware often switches it off first, and a PC without it has no second line of defence against a bad download."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			var facts []Fact
			on := 0
			for _, product := range g.Antivirus {
				facts = append(facts, Fact{product.Name, "On: " + product.On.String() + ". Up to date: " + product.UpToDate.String()})
				if product.On == model.Yes {
					on++
				}
			}
			switch {
			case g.AntivirusHealth == model.No, len(g.Antivirus) > 0 && on == 0:
				reason := i18n.T("Windows Security reports that no antivirus is switched on.")
				if len(g.Antivirus) == 0 {
					reason = i18n.T("Windows Security reports that antivirus protection needs attention.")
				}
				found = append(found, r.find("Antivirus", reason+" Files are not being checked as they are opened or downloaded.",
					i18n.T(openSecurity)+"Under Virus and threat protection, switch protection back on. If it will not stay on, or you did not switch it off yourself, treat that as a warning sign and scan the PC.", facts...))
			case g.RealTime == model.No && defenderInUse(g):
				found = append(found, r.find("Microsoft Defender",
					i18n.T("Microsoft Defender's real-time protection is switched off. Defender is installed, but it is not checking files as they are opened or downloaded."),
					i18n.T(openSecurity)+"Under Virus and threat protection > Manage settings, switch Real-time protection on. If you did not switch it off yourself, treat that as a warning sign and scan the PC.", facts...))
			}
			return
		},
	},
	{
		ID: "antivirus-out-of-date", Area: model.Protection, Severity: Medium, Topic: "antivirus",
		Title: i18n.T("Antivirus is on but out of date"),
		Why:   i18n.T("Antivirus recognises threats from a list that is renewed several times a day. With an old list it misses whatever is new."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, product := range s.Guard.Antivirus {
				if product.On == model.Yes && product.UpToDate == model.No {
					found = append(found, r.find(product.Name,
						product.Name+" is switched on, but Windows reports that its list of known threats is out of date. New threats may get past it.",
						"Open "+product.Name+" and let it update. If it keeps failing, check that the PC is online and that nothing blocks its update site.", Fact{"Antivirus", product.Name}))
				}
			}
			return
		},
	},
	{
		ID: "defender-tamper-off", Area: model.Protection, Severity: Medium, Topic: "tamper",
		Title: i18n.T("Defender's settings are not locked"),
		Why:   i18n.T("Tamper Protection stops other programs from switching Microsoft Defender off or changing its settings. Malware that gets in tries to do exactly that."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			if s.Guard.Tamper == model.No && defenderInUse(s.Guard) && s.Guard.RealTime != model.No {
				found = append(found, r.find("Tamper Protection",
					i18n.T("Tamper Protection is off, so a program with administrator rights could switch Microsoft Defender off without asking you."),
					i18n.T(openSecurity)+"Under Virus and threat protection > Manage settings, switch Tamper Protection on."))
			}
			return
		},
	},
	{
		ID: "defender-exclusions", Area: model.Protection, Severity: Medium, Topic: "exclusions",
		Title: i18n.T("Microsoft Defender has been told to skip some places"),
		Why:   i18n.T("An exclusion tells the antivirus not to look at a folder, a kind of file or a program. Developers and games sometimes need one. Malware adds its own folder to the list so that it is never scanned."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			if len(g.Exclusions) == 0 {
				return
			}
			var facts []Fact
			var values []string
			broad := ""
			for _, exclusion := range g.Exclusions {
				value := exclusion.Value
				// Defender's own log often still holds the moment it was added.
				for _, logged := range g.LoggedExclusions {
					if logged.Kind == exclusion.Kind && strings.EqualFold(logged.Value, exclusion.Value) {
						value += ", added on " + Moment(s, logged.When) + " according to Defender's own log"
					}
				}
				facts = append(facts, Fact{exclusion.Kind, value})
				values = append(values, exclusion.Value)
				if wide(exclusion, s.Folders) && broad == "" {
					broad = exclusion.Value
				}
			}
			f := r.find(plural(len(g.Exclusions), "exclusion", "exclusions"),
				i18n.T("Microsoft Defender does not scan: ")+list(values, 5)+". Anything placed there, or matching it, is never checked.",
				i18n.T(openSecurity)+"Under Virus and threat protection > Manage settings > Exclusions, remove any you did not add yourself.", facts...)
			if broad != "" {
				f.Severity = High
				f.Reason += " The exclusion " + broad + " is very wide: it covers places where downloads and temporary files land."
			}
			found = append(found, f)
			return
		},
	},
	{
		ID: "firewall-off", Area: model.Protection, Severity: High, Topic: "firewall",
		Title: i18n.T("The firewall is off"),
		Why:   i18n.T("The firewall decides which programs on other devices may start a connection to this PC. With it off, every program that is waiting for connections can be reached by anything on the same network."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			var facts []Fact
			var off []string
			for _, profile := range g.Firewall {
				facts = append(facts, Fact{i18n.T("Windows Firewall, ") + strings.ToLower(profile.Name), on(profile.On)})
				if profile.On == model.No {
					off = append(off, strings.ToLower(profile.Name))
				}
			}
			other := false
			for _, product := range g.FirewallProducts {
				facts = append(facts, Fact{product.Name, on(product.On)})
				if product.On == model.Yes && !strings.Contains(strings.ToLower(product.Name), "windows") {
					other = true
				}
			}
			switch {
			case g.FirewallHealth == model.Yes, other && g.FirewallHealth != model.No:
				// Windows Security is satisfied, or another firewall has taken over.
			case g.FirewallHealth == model.No && len(off) == 0:
				found = append(found, r.find("Firewall", i18n.T("Windows Security reports that the firewall needs attention."),
					i18n.T(openSecurity)+"Under Firewall and network protection, switch the firewall on for every kind of network.", facts...))
			case len(off) > 0:
				found = append(found, r.find("Windows Firewall",
					i18n.T("Windows Firewall is switched off for ")+list(off, 3)+". On those networks, other devices can reach every program on this PC that is waiting for connections.",
					i18n.T(openSecurity)+"Under Firewall and network protection, switch the firewall on for every kind of network. If you did not switch it off yourself, treat that as a warning sign.", facts...))
			}
			return
		},
	},
	{
		ID: "uac-off", Area: model.Protection, Severity: High, Topic: "uac",
		Title: i18n.T("Windows does not ask before giving a program full rights"),
		Why:   "User Account Control is the prompt that asks \"Do you want to allow this app to make changes?\". It is the moment at which a person can say no. With it off or silenced, any program an administrator runs can take full control of the PC without anyone seeing it happen.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			fix := i18n.T("Open the Start menu, type UAC and open Change User Account Control settings. Move the slider up to the second position from the top, which is Windows' own default.")
			switch {
			case g.UAC == model.No:
				found = append(found, r.find(i18n.T("User Account Control"),
					i18n.T("User Account Control is switched off completely. Every program an administrator runs gets full rights at once, and nothing asks first."), fix))
			case g.UACSilent == model.Yes:
				f := r.find(i18n.T("User Account Control"),
					i18n.T("User Account Control is set to never notify. Windows still separates ordinary rights from full rights, but when a program asks for full rights an administrator's account gives them silently. The prompt that would let you say no never appears."), fix)
				f.Severity = Medium
				f.Title = i18n.T("Windows gives programs full rights without asking")
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "updates-old", Area: model.Protection, Severity: Medium, Topic: "updates",
		Title: i18n.T("Windows has not installed an update for some time"),
		Why:   i18n.T("Microsoft fixes security holes in Windows every month. Each month without updates leaves known holes open, and those are the ones attackers use most."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			if !g.UpdateKnown || s.Taken.IsZero() {
				return
			}
			days := int(s.Taken.Sub(g.LastUpdate).Hours() / 24)
			if days <= 45 {
				return
			}
			f := r.find("Windows Update",
				i18n.T("The last update Windows installed was on ")+g.LastUpdate.Format("2 January 2006")+", "+strconv.Itoa(days)+" days ago. Updates normally arrive every month.",
				i18n.T("Open Settings, go to Windows Update (inside Update and Security on Windows 10) and choose Check for updates. If nothing is offered, check whether this version of Windows still receives updates."),
				Fact{"Windows", strings.TrimSpace(s.Windows + " build " + g.Build)}, Fact{"Last update installed", g.LastUpdate.Format("2 January 2006")})
			if days > 180 {
				f.Severity = High
			}
			found = append(found, f)
			return
		},
	},
	{
		ID: "hosts-entries", Area: model.Protection, Severity: Medium, Topic: "hosts",
		Title: i18n.T("The hosts file sends website names somewhere else"),
		Why:   i18n.T("Before Windows asks the internet where a website is, it looks in a small text file called hosts. A line there can silently send a name to any address, for instance a bank's name to a fake copy, or stop security sites from being reached at all."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			var blockedSecurity, redirected, blocked, home []string
			var facts []Fact
			for _, entry := range s.Guard.Hosts {
				for _, name := range entry.Names {
					switch {
					case strings.EqualFold(name, "localhost"):
						continue // the one line every hosts file may have
					case nowhere(entry.Address) && guarded(name):
						blockedSecurity = append(blockedSecurity, name)
					case nowhere(entry.Address):
						blocked = append(blocked, name)
					case homeName(name):
						home = append(home, name)
					default:
						redirected = append(redirected, name+" to "+entry.Address)
					}
					if len(facts) < 40 {
						facts = append(facts, Fact{entry.Address, name})
					}
				}
			}
			facts = append([]Fact{{"File", s.Guard.HostsPath}}, facts...)
			edit := i18n.T("The file is plain text and can be read in Notepad. Changing it needs administrator rights. If you did not add these lines yourself, ask someone who knows Windows well before removing them.")
			if len(blockedSecurity) > 0 {
				f := r.find(plural(len(blockedSecurity), i18n.T("security or update site blocked"), i18n.T("security or update sites blocked")),
					i18n.T("The hosts file stops this PC from reaching ")+list(blockedSecurity, 5)+". Blocking update and antivirus sites is what malware does to keep a PC from being cleaned. Some people block Microsoft sites on purpose to stop data being sent.", edit, facts...)
				f.Severity = High
				found = append(found, f)
			}
			if len(redirected) > 0 {
				found = append(found, r.find(plural(len(redirected), "name redirected", "names redirected"),
					i18n.T("The hosts file sends ")+list(redirected, 4)+". Anyone opening such a name on this PC lands at that address instead of the real site.", edit, facts...))
			}
			if len(blocked) > 0 {
				f := r.find(plural(len(blocked), "site blocked", "sites blocked"),
					i18n.T("The hosts file blocks ")+list(blocked, 5)+" by pointing the names at this PC itself. Ad blockers and some programs' licence checks do this. It is harmless if you or a program you trust added the lines.", edit, facts...)
				f.Severity = Low
				found = append(found, f)
			}
			if len(home) > 0 && len(redirected) == 0 && len(blockedSecurity) == 0 {
				f := r.find(plural(len(home), "local name", "local names"),
					"The hosts file gives addresses to "+list(home, 5)+". These are names used only on this PC or its own network, the kind developer tools such as Docker add.", i18n.T("Nothing needs doing if you use such tools. ")+edit, facts...)
				f.Severity = Low
				found = append(found, f)
			}
			// The hosts file can also be moved, so that the one everybody
			// checks stays clean.
			if usual := winpath.Join(s.Folders.System, `drivers\etc\hosts`); s.Guard.HostsPath != "" && s.Folders.System != "" && !winpath.Same(s.Guard.HostsPath, usual) {
				f := r.find("Hosts file moved",
					i18n.T("Windows is set to read its hosts file from ")+s.Guard.HostsPath+" and not from the usual place, "+usual+". Moving it is a way to keep changes out of sight.",
					i18n.T("This is set in the registry under Tcpip\\Parameters, value DataBasePath. Unless you changed it yourself, have someone who knows Windows well look at it."), Fact{"File", s.Guard.HostsPath})
				f.Severity = High
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "disk-not-encrypted", Area: model.Protection, Severity: Low,
		Title: i18n.T("The Windows disk is not encrypted"),
		Why:   i18n.T("Encryption (BitLocker, or Device encryption) scrambles the disk so that it can only be read after signing in. Without it, anyone who takes the PC or the disk can read every file on it without knowing the password. It matters most for a laptop."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, volume := range s.Guard.Volumes {
				r.at(DiskRef(volume.Drive))
				if volume.Encrypted == model.No && s.Folders.Windows != "" && strings.EqualFold(volume.Drive, s.Folders.Windows[:2]) {
					// The state is worth saying only when it is more than "off",
					// such as encryption that was started and is paused.
					state := ""
					if st := strings.ToLower(volume.State); st != "" && st != "off" {
						state = " (" + st + ")"
					}
					found = append(found, r.find("Drive "+volume.Drive,
						"Drive "+volume.Drive+", which holds Windows and your files, is not encrypted"+state+". If the PC is lost or stolen, its files can be read without your password.",
						i18n.T("Search the Start menu for BitLocker or for Device encryption and switch it on. Save the recovery key somewhere other than this PC first: without it, a fault can lock you out of your own files."),
						Fact{"Drive", volume.Drive}, Fact{"Encryption", volume.State}))
				}
			}
			return
		},
	},
	{
		ID: "secure-boot-off", Area: model.Protection, Severity: Low, Topic: "secureboot",
		Title: i18n.T("Secure Boot is off"),
		Why:   i18n.T("Secure Boot lets the PC start only software its maker or Microsoft has signed, which blocks malware that loads before Windows does and so hides from it."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			if s.Guard.SecureBoot == model.No {
				found = append(found, r.find("Secure Boot",
					i18n.T("Secure Boot is switched off, so the PC will start any boot software, signed or not. People switch it off to run other operating systems or older hardware."),
					i18n.T("It is switched on in the PC's firmware settings (often called BIOS or UEFI), reached with a key such as F2 or Del while the PC starts. Leave it if you switched it off for a reason.")))
			}
			return
		},
	},
}

// on words a yes or no for a switch.
func on(a model.Answer) string {
	switch a {
	case model.Yes:
		return "On"
	case model.No:
		return "Off"
	}
	return "Not known"
}

// wide reports whether an exclusion covers a place where unwanted files
// usually land, or a whole kind of program file.
func wide(e model.Exclusion, f model.Folders) bool {
	value := strings.ToLower(winpath.Tidy(e.Value))
	switch e.Kind {
	case "File type":
		switch strings.TrimLeft(value, ".*") {
		case "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr", "com", "msi", "sys":
			return true
		}
		return false
	case "Program":
		return false
	}
	if len(value) <= 3 { // a whole drive
		return true
	}
	for _, place := range []string{f.Users, f.Profile, f.Temp, f.Downloads, f.Windows, f.System, f.ProgramData, winpath.Join(f.Profile, "AppData"), winpath.Join(f.Profile, `AppData\Local`), winpath.Join(f.Profile, `AppData\Roaming`), winpath.Join(f.Profile, "Desktop")} {
		if place != "" && winpath.Same(value, place) {
			return true
		}
	}
	return false
}
