package rules

import (
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
	"lazascope/internal/winpath"
)

// aboutExtension gathers the evidence that goes with a browser extension.
func aboutExtension(e model.Startup) []Fact {
	x := e.Extension
	facts := []Fact{{"Extension", x.Name}, {"Browser", x.Browser + ", profile " + x.Profile}, {"Where it came from", x.Source.String()}}
	add := func(label, value string) {
		if value != "" {
			facts = append(facts, Fact{label, value})
		}
	}
	add("Version", x.Version)
	add("What it may do", extensionMay(x))
	add("Its number in the browser", x.ID)
	add("Folder", x.Folder)
	return facts
}

// extensionMay puts an extension's rights into one sentence.
func extensionMay(x *model.Extension) string {
	may := append([]string{}, x.May...)
	if x.EverySite {
		may = append([]string{"read and change the pages of every website you visit"}, may...)
	}
	if len(may) == 0 {
		return ""
	}
	text := list(may, 8)
	return strings.ToUpper(text[:1]) + text[1:]
}

// removeExtension says how to switch an extension off in its browser.
func removeExtension(x *model.Extension) string {
	return "To switch it off, open " + x.Browser + ", open its menu and choose Extensions (in Firefox: Add-ons and themes), find it and turn its switch off or choose Remove."
}

// about gathers the evidence that goes with a start-up entry.
func about(e model.Startup) []Fact {
	if e.Extension != nil {
		return aboutExtension(e)
	}
	works := e.Works()
	facts := []Fact{{"Entry", e.Shown()}, {"Kind", e.Kind.String()}, {"Recorded in", e.Where}}
	add := func(label, value string) {
		if value != "" {
			facts = append(facts, Fact{label, value})
		}
	}
	add("Command", e.Command)
	add("File", works.Path)
	if e.Program.Path != "" && !winpath.Same(e.Program.Path, works.Path) {
		add("Started through", e.Program.Path)
	}
	if works.Exists && works.Program {
		add("Signature", Signature(works))
		add("The file says it is", Claim(works))
	}
	add("Starts", e.Trigger)
	add("Runs as", e.Account)
	if works.Script != nil && len(works.Script.Signs) > 0 {
		add("Going by the script's text", strings.Join(works.Script.Signs, " "))
	}
	return facts
}

// Signature says in a line who signed a file, or that nobody did.
func Signature(f model.File) string {
	switch f.Signature.Status {
	case sigcheck.Signed:
		text := "Signed by " + f.Signature.Maker()
		if f.Signature.Source == sigcheck.Catalogue {
			text += " (through a Windows catalogue)"
		}
		return text
	case sigcheck.Unsigned:
		return "Not signed"
	case sigcheck.Invalid:
		text := "Signature not valid"
		if f.Signature.Signer != "" {
			text += ", in the name of " + f.Signature.Signer
		}
		return text + ". " + f.Signature.Problem
	}
	return "Could not be checked. " + f.Signature.Problem
}

// Claim joins what a file says of itself. Anyone can write anything into
// a file, so this is a claim and not proof.
func Claim(f model.File) string {
	var parts []string
	for _, part := range []string{f.Description, f.Company} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ", by ")
}

// stop says how to switch a kind of start-up entry off in Windows itself.
func stop(kind model.StartupKind) string {
	switch kind {
	case model.RunKey, model.RunOnceKey, model.StartupFolder, model.StoreApp:
		return "To stop it starting, open Task Manager (Ctrl + Shift + Esc), go to the Start-up tab and switch it off. That does not delete anything and can be undone."
	case model.ScheduledTask:
		return "To stop it, open Task Scheduler from the Start menu, find the task and choose Disable. That does not delete anything and can be undone."
	case model.Service:
		return "To stop it, open Services from the Start menu, open the service and set Startup type to Disabled. Only do this if you are sure what it is: some services are needed for Windows or your hardware to work."
	case model.Driver:
		return "Do not remove a driver by hand. If you do not recognise it, look up its name and maker, and uninstall the program it came with from Settings > Apps."
	}
	return "If you did not set this up yourself, ask someone who knows Windows well to look at it."
}

const known = "If you know this program and installed it yourself, nothing needs doing. If you do not, search the web for its file name and maker before touching it. "

// ownScript is the advice for a script, which has no maker to look up but
// can be read.
const ownScript = "If you wrote this script or set it up yourself, nothing needs doing. If you did not, read it before anything else: open Notepad, then drag the file into its window. Do not double-click the file, because that runs it. "

var startupRules = []Rule{
	{
		ID: "startup-altered", Area: model.StartsWithWindows, Severity: High,
		Title: "Starts by itself and was changed after its maker signed it",
		Why:   "A digital signature breaks if a single byte of the file changes. A signed program that no longer matches its signature has been altered since it left its maker. Unwanted code that hides inside another program does that.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if works := e.Works(); e.Enabled && works.Exists && works.Signature.Changed() {
					found = append(found, r.find(e.Shown(),
						"This program carries a maker's signature, but the file no longer matches it. Something has changed the file since it was signed. A damaged download or a badly made patch can do that, and so can unwanted code that hides inside another program.",
						"Reinstall the program from its maker's website and scan the PC with your antivirus. "+stop(e.Kind), about(e)...))
				}
			}
			return
		},
	},
	{
		ID: "startup-system-name", Area: model.StartsWithWindows, Severity: High,
		Title: "Named like a part of Windows, but not where Windows keeps it",
		Why:   "Windows' own programs, such as svchost.exe, live in the Windows folder. A file with one of those names anywhere else is a classic disguise: it hopes to be passed over in a list.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				for _, file := range distinct(e.Program, e.Target) {
					if !e.Enabled {
						continue
					}
					if Disguised(file.Path, s.Folders) {
						found = append(found, r.find(e.Shown(),
							winpath.Base(file.Path)+" is the name of a part of Windows, and the real one is in "+s.Folders.Windows+". This one is in "+winpath.Dir(file.Path)+". A program that borrows a Windows name in another folder is usually trying not to be noticed."+stillMicrosoft(file),
							"Unless you put it there yourself, treat it as suspect: scan the file with your antivirus and ask someone who knows Windows well. "+stop(e.Kind), about(e)...))
					} else if of, ok := Lookalike(file.Path); ok {
						found = append(found, r.find(e.Shown(),
							winpath.Base(file.Path)+" is spelt almost like "+of+", a part of Windows, but it is not that file. Names one letter away from a Windows name are chosen to be misread.",
							"Unless you know what this program is, treat it as suspect: scan the file with your antivirus and ask someone who knows Windows well. "+stop(e.Kind), about(e)...))
					}
				}
			}
			return
		},
	},
	{
		ID: "startup-scrambled-command", Area: model.StartsWithWindows, Severity: High,
		Title: "Starts a scripting tool with a scrambled command",
		Why:   "PowerShell, cmd and their relatives run whatever they are handed. Attackers hide their instructions from people and from antivirus by encoding them, breaking the words up, or fetching the real commands from the internet at the last moment.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if !e.Enabled || e.Command == "" {
					continue
				}
				signs := Scrambled(e.Program.Path, e.Command)
				if len(signs) == 0 {
					continue
				}
				found = append(found, r.find(e.Shown(),
					"This entry runs "+winpath.Base(e.Program.Path)+", a tool that carries out whatever commands it is given, and the commands are hidden. "+strings.Join(signs, " ")+" Honest software has little reason to hide what it runs at start-up.",
					"Do not run the command to see what it does. Unless you set this up yourself, show it to someone who knows Windows well. "+stop(e.Kind), about(e)...))
			}
			return
		},
	},
	{
		ID: "startup-logon-setting", Area: model.StartsWithWindows, Severity: High,
		Title: "Windows' sign-in programs have been changed",
		Why:   "Two settings name what Windows runs while a user signs in: the desktop (explorer.exe) and a helper (userinit.exe). Anything added there runs at every sign-in before the user sees the desktop, which makes these settings a favourite hiding place.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if e.Kind != model.LogonSetting {
					continue
				}
				usual := "explorer"
				if strings.EqualFold(e.Name, "Userinit") {
					usual = "userinit"
				}
				if winpath.Stem(e.Program.Path) == usual && InWindows(e.Program.Path, s.Folders) && strings.TrimSpace(e.Arguments) == "" {
					continue
				}
				found = append(found, r.find(e.Name+": "+e.Command,
					"The "+e.Name+" setting normally names only "+usual+".exe in the Windows folder. Here it also runs "+e.Command+". Whatever is named there starts at every sign-in, before the desktop appears.",
					"Unless a kiosk or a custom desktop was set up on purpose, this needs looking at by someone who knows Windows well. Do not edit the setting by guesswork: a wrong value can stop Windows from signing in.", about(e)...))
			}
			return
		},
	},
	{
		ID: "startup-debugger", Area: model.StartsWithWindows, Severity: Medium,
		Title: "Another program is set to run in place of a normal one",
		Why:   "Windows has a developer setting called a debugger: when the named program is opened, Windows starts the debugger in its place. It is a known trick for swapping one program for another, most famously to open a command window from the sign-in screen without a password.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if e.Kind != model.DebuggerSetting || !e.Enabled {
					continue
				}
				f := r.find(e.Subject,
					"Whenever "+e.Subject+" is opened, Windows runs this in its place: "+e.Command+". Some tools set this on purpose, for example to replace Task Manager with a fuller one. It is also a known way to hijack a program.",
					"If you installed a tool that replaces "+e.Subject+", this is that tool's doing. If not, ask someone who knows Windows well to remove the setting.", about(e)...)
				// The programs reachable from the sign-in screen without a password.
				switch strings.ToLower(e.Subject) {
				case "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe":
					f.Severity = High
					f.Reason = e.Subject + " can be opened from the sign-in screen before anyone has typed a password. A debugger set for it lets whoever sits at the PC run this in its place, with full rights: " + e.Command + ". This is a well-known back door."
				}
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "startup-loaded-library", Area: model.StartsWithWindows, Severity: Medium,
		Title: "A library is set to load into every program",
		Why:   "An old Windows setting (AppInit_DLLs) loads the named libraries into every program that shows a window. Very little modern software uses it, and it gives whatever is named there a view into almost everything the user does.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if e.Kind != model.LoadedLibrary || !e.Enabled {
					continue
				}
				f := r.find(e.Shown(),
					"Windows is set to load "+e.Command+" into every program that shows a window. Few programs need that, and whatever is loaded this way can watch or change what those programs do.",
					"Find out which program this library belongs to. If you do not recognise it, ask someone who knows Windows well.", about(e)...)
				if works := e.Works(); works.Exists && works.Program && !works.Signature.Trusted() {
					f.Severity = High
				}
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "startup-temp-folder", Area: model.StartsWithWindows, Severity: Medium,
		Title: "Starts from a temporary or download folder",
		Why:   "Installed software lives in Program Files. Temporary and download folders are where files land from the internet and where installers unpack, so something that starts from there at every boot was probably never properly installed. Malware often runs from these folders because any program may write to them.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if !e.Enabled {
					continue
				}
				for _, file := range distinct(e.Program, e.Target) {
					kind, ok := Temporary(file.Path, s.Folders)
					if !ok {
						continue
					}
					f := r.find(e.Shown(),
						"It starts "+file.Path+", which is in "+kind+". Properly installed software does not live there. A portable program you saved and chose to start with Windows would look like this, and so would something unwanted.",
						known+stop(e.Kind), about(e)...)
					if file.Exists && file.Program && !file.Signature.Trusted() {
						f.Severity = High
						f.Reason += " The file is also not signed by a known maker."
					}
					found = append(found, f)
					break
				}
			}
			return
		},
	},
	{
		ID: "startup-user-folder", Area: model.StartsWithWindows, Severity: Medium,
		Title: "A task, service or driver runs from a user's folder",
		Why:   "Services, drivers and most scheduled tasks belong to the whole PC and are installed into Program Files or Windows, where only an administrator can change them. One that runs a file from a user's own folder is unusual for real software, and the file can be swapped by any program that user runs.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if !e.Enabled || (e.Kind != model.ScheduledTask && e.Kind != model.Service && e.Kind != model.Driver) {
					continue
				}
				works := e.Works()
				if !works.Exists || !UserFolder(works.Path, s.Folders) {
					continue
				}
				if _, temporary := Temporary(works.Path, s.Folders); temporary {
					continue // said already, by the rule above
				}
				// Plenty of honest programs install for one user only and
				// keep themselves up to date with a task. Those are signed.
				if e.Kind == model.ScheduledTask && works.Program && works.Signature.Trusted() {
					continue
				}
				what := "The file is not signed by a known maker."
				if runsScript(e) {
					what = "The file is a script: a text file of commands, which almost never carries a maker's signature."
				} else if !works.Program {
					what = "The file is not a program, so there is no maker's signature to check."
				} else if works.Signature.Trusted() {
					what = "The file is signed by " + works.Signature.Maker() + "."
				}
				advice := known
				if runsScript(e) {
					advice = ownScript
				}
				found = append(found, r.find(e.Shown(),
					"This "+strings.ToLower(e.Kind.String())+" runs "+works.Path+", which is in a user's own folder. "+what+" Software for the whole PC is normally installed where only an administrator can change it. A file here can be replaced by any program that user runs.",
					advice+stop(e.Kind), about(e)...))
			}
			return
		},
	},
	{
		ID: "startup-unsigned", Area: model.StartsWithWindows, Severity: Medium,
		Title: "Starts by itself and is not signed by its maker",
		Why:   "A digital signature is a maker's seal on a file. Nearly all commercial software is signed, so that Windows can show who made it and that nobody has changed it since. Something that starts by itself with no valid signature is not proof of harm, as small free tools are often unsigned, but it cannot be traced to anyone.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				works := e.Works()
				if !e.Enabled || !works.Exists || !works.Program || works.Signature.Trusted() || works.Signature.Changed() || works.Signature.Status == sigcheck.Unknown {
					continue
				}
				reason := "This program starts by itself and carries no maker's signature, so Windows cannot say who made it or whether it has been changed. Small free tools and programs people build themselves are often unsigned. So is most malware."
				if works.Signature.Status == sigcheck.Invalid {
					reason = "This program starts by itself and its signature does not check out. " + works.Signature.Problem + " Windows therefore cannot vouch for who made it. LazaScope checks without going online, so a certificate Windows has never seen before can show up this way."
				}
				if works.Company != "" {
					reason += " The file says it comes from " + works.Company + ", but anyone can write that into a file."
				}
				found = append(found, r.find(e.Shown(), reason, known+stop(e.Kind), about(e)...))
			}
			return
		},
	},
	{
		ID: "startup-script", Area: model.StartsWithWindows, Severity: Medium,
		Title: "Starts a script by itself",
		Why:   "A script is a text file of commands that a scripting tool carries out. Scripts are easy to write, almost never carry a maker's signature, and can be rewritten by anything able to change the file. People use them to open their own things at sign-in, and unwanted software uses them to keep itself going. Scripts kept in the Windows folder or Program Files, where only an administrator can change them, are left out. A script run by a scheduled task or a service is only good to know, because administrators and PC makers set those up for upkeep.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				if !e.Enabled || !runsScript(e) {
					continue
				}
				works := e.Works()
				if Protected(works.Path, s.Folders) {
					continue
				}
				upkeep := e.Kind == model.ScheduledTask || e.Kind == model.Service
				switch {
				case upkeep && UserFolder(works.Path, s.Folders):
					continue // said already, by the rule for tasks and services that run from a user's folder
				case !upkeep && e.Kind != model.RunKey && e.Kind != model.RunOnceKey && e.Kind != model.StartupFolder:
					continue // the sign-in settings and the like have rules of their own
				}
				what := "This entry"
				if upkeep {
					what = "This " + strings.ToLower(e.Kind.String())
				}
				reason := what + " runs the script " + works.Path
				if e.Program.Path != "" && !winpath.Same(e.Program.Path, works.Path) {
					reason += ", through " + winpath.Base(e.Program.Path)
				}
				reason += ". A script is a text file of commands. Unlike a program it almost never carries a maker's signature, so nothing shows who wrote it or whether it has been changed since."
				if UserFolder(works.Path, s.Folders) {
					reason += " This one is in a user's own folder, where any program that user runs can rewrite it."
				} else {
					reason += " This one is kept outside the Windows and Program Files folders, where installed software normally lives."
				}
				severity := r.Severity
				advice := ownScript
				switch {
				case EncodedScript(works.Path):
					severity = High
					reason += " Its name says it is an encoded script, saved in a scrambled form so that it cannot be read. Honest scripts are rarely hidden like that."
					advice = "Unless you set this up yourself, show it to someone who knows Windows well. Do not double-click the file, because that runs it. "
				case upkeep:
					severity = Low
					reason += " Administrators and PC makers set up scripts like this for upkeep, so it is only good to know, unless you do not recognise it."
				default:
					reason += " People set scripts like this up themselves, to open things when they sign in. Unwanted software uses them too, because they are easy to make and easy to overlook."
				}
				f := r.find(e.Shown(), reason, advice+stop(e.Kind), about(e)...)
				f.Severity = severity
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "extension-not-from-store", Area: model.StartsWithWindows, Severity: Medium,
		Title: "A browser extension did not come from the browser's store",
		Why:   "An extension loads whenever its browser is open, and many may read and change every page you visit, including what you type into them. The browsers' stores check what they hand out, and browsers make it awkward on purpose to add an extension any other way. One that got in from a file, from a folder or through another program skipped that check. Developers load their own this way. So does software that wants to change your searches or read your pages.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				x := e.Extension
				if x == nil || !x.Enabled {
					continue
				}
				how := ""
				switch x.Source {
				case model.FromFile:
					how = "It was added by hand from a file, not through the browser's store."
				case model.Unpacked:
					how = "It is loaded from a folder on this PC, which needs the browser's developer mode. Whoever can change that folder can change what the extension does."
				case model.FromOutside:
					how = "Another program on this PC put it into the browser. Honest software does that now and then, for example an antivirus adding its web shield. It is also how unwanted toolbars arrive."
				case model.CommandLine:
					how = "It is loaded by a switch on the line that starts the browser. That is not how extensions are installed: something changed the browser's shortcut or the way it is started."
				case model.SourceUnknown:
					how = "The browser's record does not say where it came from."
				default:
					continue
				}
				r.at(StartupRef(i))
				reason := x.Name + " is switched on in " + x.Browser + " (profile " + x.Profile + "). " + how
				if may := extensionMay(x); may != "" {
					reason += " It may " + strings.ToLower(may[:1]) + may[1:] + "."
				}
				f := r.find(x.Name, reason, "If you added it yourself, or it belongs to a program you use, nothing needs doing. If you do not recognise it, switch it off. "+removeExtension(x), about(e)...)
				if x.Source == model.CommandLine {
					f.Severity = High
				}
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "extension-forced", Area: model.StartsWithWindows, Severity: Medium,
		Title: "A browser extension is forced on by a policy",
		Why:   "A policy is a setting that overrides the user's own choices. Workplaces and schools use one to put an extension on every PC they manage, and such an extension cannot be removed from inside the browser. On a PC nobody manages, a forced extension is a known trick of unwanted software: it uses the policy to make itself hard to remove.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				x := e.Extension
				if x == nil || !x.Enabled || x.Source != model.ByPolicy {
					continue
				}
				r.at(StartupRef(i))
				reason := x.Name + " is forced on in " + x.Browser + " (profile " + x.Profile + ") by a policy, so the browser will not let you remove it."
				if may := extensionMay(x); may != "" {
					reason += " It may " + strings.ToLower(may[:1]) + may[1:] + "."
				}
				found = append(found, r.find(x.Name, reason,
					"If this PC is managed by your workplace or school, this is their doing and nothing needs doing. If it is your own PC and you never set a policy, ask someone who knows Windows well: the policy has to be removed before the extension can be.", about(e)...))
			}
			return
		},
	},
	{
		ID: "startup-missing-file", Area: model.StartsWithWindows, Severity: Low,
		Title: "Points at a file that is no longer there",
		Why:   "When a program is removed, the entry that started it is sometimes left behind. It does nothing, because there is nothing to start. It is worth tidying, and worth knowing about in case the file comes back.",
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				r.at(StartupRef(i))
				works := e.Works()
				if !e.Enabled || works.Path == "" || works.Exists || !winpath.Absolute(works.Path) {
					continue
				}
				// Windows itself ships tasks and drivers for features that are
				// not installed on every PC. Those are not leftovers.
				if (e.Kind == model.ScheduledTask && strings.HasPrefix(strings.ToLower(e.Name), `\microsoft\`)) || (e.Kind == model.Driver && InWindows(works.Path, s.Folders)) {
					continue
				}
				found = append(found, r.find(e.Shown(),
					"This entry is meant to start "+works.Path+", but there is no such file. It is most likely left over from a program that was removed. It does no harm as it is.",
					"You can leave it as it is. "+stop(e.Kind), about(e)...))
			}
			return
		},
	},
}

// runsScript reports whether the file an entry works with is a script: one
// by its name, or any file that is not a program and is handed to a tool
// that treats whatever it is given as a script.
func runsScript(e model.Startup) bool {
	works := e.Works()
	if !works.Exists || works.Program {
		return false
	}
	if Script(works.Path) {
		return true
	}
	if e.Target.Path == "" || winpath.Same(e.Target.Path, e.Program.Path) {
		return false
	}
	switch winpath.Stem(e.Program.Path) {
	case "wscript", "cscript", "mshta":
		return true
	}
	return false
}

// distinct returns the files an entry involves, each once: the program it
// starts and, when that program is only a go-between, the file it is handed.
func distinct(program, target model.File) []model.File {
	if target.Path == "" || winpath.Same(program.Path, target.Path) {
		return []model.File{program}
	}
	if program.Path == "" {
		return []model.File{target}
	}
	return []model.File{target, program}
}

// stillMicrosoft adds a note for a disguised file that really is
// Microsoft's: a copy of a Windows program under another name keeps its
// signature, and that must not be read as "safe".
func stillMicrosoft(f model.File) string {
	if !f.Signature.FromMicrosoft() {
		return ""
	}
	note := " The file does carry Microsoft's signature, which means it is a copy of a real Windows program"
	if f.Original != "" && !strings.EqualFold(f.Original, winpath.Base(f.Path)) && !strings.EqualFold(strings.TrimSuffix(strings.ToLower(f.Original), ".mui"), strings.ToLower(winpath.Base(f.Path))) {
		note += ", built under the name " + f.Original
	}
	return note + ". Copying a Windows tool to another place under another name is itself a known trick."
}
