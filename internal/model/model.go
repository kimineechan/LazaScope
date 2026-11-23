// Package model holds the plain facts LazaScope gathers about a PC: what
// starts by itself, what is running, what is connected, and how the PC is
// protected.
//
// It is data only. The collectors fill it in, the rules read it, and the
// window and the report show it. Nothing here calls Windows, so the rules
// can be tested with made-up PCs.
package model

import (
	"strings"
	"time"

	"lazascope/internal/sigcheck"
)

// Area is one of the six things the overview page gives a light to.
type Area int

const (
	Protection Area = iota
	StartsWithWindows
	RunningNow
	Connections
	Accounts
	Health
	Areas // how many there are
)

func (a Area) String() string {
	switch a {
	case Protection:
		return "Protection"
	case StartsWithWindows:
		return "Starts with Windows"
	case RunningNow:
		return "Running now"
	case Connections:
		return "Internet connections"
	case Accounts:
		return "Accounts and remote access"
	case Health:
		return "PC health"
	}
	return ""
}

// Answer is yes, no, or not known. Much of what a PC is asked without
// administrator rights has no answer, and that must not be taken for a no.
type Answer int

const (
	NotKnown Answer = iota
	Yes
	No
)

// Say turns a true or false from Windows into an Answer.
func Say(yes bool) Answer {
	if yes {
		return Yes
	}
	return No
}

func (a Answer) String() string {
	switch a {
	case Yes:
		return "yes"
	case No:
		return "no"
	}
	return "not known"
}

// File is what is known about one file on disk that something runs.
type File struct {
	Path      string
	Exists    bool
	Program   bool            // it is a Windows program or library, not a script or a document
	Signature sigcheck.Result // who signed it

	// What the file says of itself. Anyone can write anything here, so these
	// are claims, unlike the signature.
	Company     string
	Description string
	Product     string
	Version     string
	Original    string // the name the file was built under

	Size     int64
	Modified time.Time

	Script *Script // for a script that could be read: what its text shows
}

// Script is what the text of a script file shows. It is a reading of the
// text and not a test: nothing was run.
type Script struct {
	Lines []string // how it begins: its first lines that are not empty
	More  bool     // it goes on after those lines
	Signs []string // what it does, each as a sentence
}

// Maker names who made the file as well as can be said: the name on a
// signature that holds, or else the file's own claim, marked as one.
func (f File) Maker() string {
	if f.Path == "" {
		return ""
	}
	if !f.Exists {
		return "File not found"
	}
	if f.Signature.Status == sigcheck.Signed || !f.Program {
		if f.Signature.Status == sigcheck.Signed {
			return f.Signature.Maker()
		}
		return "Not a program file"
	}
	maker := f.Signature.Maker()
	if f.Company != "" && f.Signature.Status == sigcheck.Unsigned {
		maker += " (says " + f.Company + ")"
	}
	return maker
}

// StartupKind is a way of starting by itself.
type StartupKind int

const (
	RunKey          StartupKind = iota // a line in the registry's Run list
	RunOnceKey                         // the same, used once and then removed
	StartupFolder                      // a file or shortcut in a Startup folder
	StoreApp                           // an app from the Microsoft Store that asked to start at sign-in
	ScheduledTask                      // a task in Task Scheduler
	Service                            // a background program Windows starts and keeps running
	Driver                             // a part that runs inside Windows itself, usually for hardware
	LogonSetting                       // what Windows runs as a user signs in
	DebuggerSetting                    // a program set to run in place of another
	LoadedLibrary                      // a library pushed into every program that shows a window
)

func (k StartupKind) String() string {
	switch k {
	case RunKey:
		return "Registry Run"
	case RunOnceKey:
		return "Registry RunOnce"
	case StartupFolder:
		return "Startup folder"
	case StoreApp:
		return "Store app"
	case ScheduledTask:
		return "Scheduled task"
	case Service:
		return "Service"
	case Driver:
		return "Driver"
	case LogonSetting:
		return "Sign-in setting"
	case DebuggerSetting:
		return "Debugger setting"
	case LoadedLibrary:
		return "Loaded library"
	}
	return ""
}

// Explain says in one line what a kind of start-up entry is.
func (k StartupKind) Explain() string {
	switch k {
	case RunKey:
		return "A line in the registry (Windows' settings database) that starts a program each time someone signs in."
	case RunOnceKey:
		return "A line in the registry that starts a program at the next sign-in, once, and is then removed. Installers use it to finish after a restart."
	case StartupFolder:
		return "A file or shortcut in a Startup folder. Windows opens everything in that folder at sign-in."
	case StoreApp:
		return "An app from the Microsoft Store that asked to start when you sign in."
	case ScheduledTask:
		return "A task in Task Scheduler, the part of Windows that starts programs at set times or when something happens."
	case Service:
		return "A background program that Windows starts by itself, before anyone signs in, and keeps running."
	case Driver:
		return "A part that runs inside Windows itself with full control, usually to work a piece of hardware."
	case LogonSetting:
		return "A setting that names the programs Windows runs while a user signs in."
	case DebuggerSetting:
		return "A setting that makes Windows start a different program whenever a named program is opened. It exists for developers."
	case LoadedLibrary:
		return "A setting that makes Windows load a library into every program that shows a window."
	}
	return ""
}

// Startup is one thing set to start by itself.
type Startup struct {
	Kind     StartupKind
	Name     string // the entry's own name
	Title    string // a friendlier name, when Windows has one, such as a service's display name
	Where    string // where it is recorded: a registry key, a folder or a task's path
	AllUsers bool   // it applies to every account on the PC, not only this one
	Command  string // what the entry says to run, as stored

	Program   File   // the program that command starts
	Arguments string // what the program is told
	Target    File   // the file that does the work: the program itself, or the library or script it is handed
	Subject   string // for a debugger setting, the program it is set for

	Enabled     bool   // false when switched off, in Task Manager or in Task Scheduler
	Running     bool   // a service or driver that is running now
	Account     string // the account a service or task runs as
	Trigger     string // when a task starts
	Description string
	Untraced    bool // the command could not be followed to a file
}

// Works returns the file that does the entry's work.
func (s Startup) Works() File {
	if s.Target.Path != "" {
		return s.Target
	}
	return s.Program
}

// Shown returns the name to show for the entry.
func (s Startup) Shown() string {
	if s.Title != "" {
		return s.Title
	}
	return s.Name
}

// Process is one running program.
type Process struct {
	PID, Parent uint32
	Name        string
	File        File // File.Path is empty when Windows would not say where the program is
	Command     string
	User        string
	Session     uint32
	Started     time.Time
	Services    []string // the services running inside it

	ParentGone    bool // the program that started it has closed since
	CommandHidden bool // its command line can only be read with administrator rights
	Self          bool // it is the program taking this look
}

// Reach is how far away the other end of a connection is, or for a program
// waiting for connections, who could reach it.
type Reach int

const (
	ThisPC       Reach = iota // nothing leaves the PC
	LocalNetwork              // the home or office network
	Internet                  // anywhere
)

func (r Reach) String() string {
	switch r {
	case ThisPC:
		return "This PC only"
	case LocalNetwork:
		return "Local network"
	}
	return "Internet"
}

// Connection is one network connection, or one port a program waits on.
type Connection struct {
	Protocol   string // TCP or UDP
	Listening  bool   // the program waits for others to connect
	State      string
	Local      string
	LocalPort  int
	Remote     string
	RemotePort int
	Reach      Reach

	PID      uint32
	Process  string
	File     File
	Services []string
}

// SecurityProduct is an antivirus or firewall as Windows Security lists it.
type SecurityProduct struct {
	Name     string
	On       Answer
	UpToDate Answer
}

// FirewallProfile is one of the three sets of firewall rules Windows keeps:
// for a work domain, for private networks and for public ones.
type FirewallProfile struct {
	Name string
	On   Answer
}

// Exclusion is something Microsoft Defender has been told not to scan.
type Exclusion struct {
	Kind  string // Folder or file, File type, Program
	Value string
}

// Detection is something Microsoft Defender found and wrote in its log.
type Detection struct {
	When     time.Time
	Threat   string // Defender's name for it, such as Trojan:Win32/Example.A
	Severity string // Defender's own word: Low, Moderate, High or Severe
	Category string // such as Trojan, or Suspicious Behaviour
	Path     string // the file or other thing it was found in
	Action   string // what Defender did, such as Quarantine; "" when the log does not say
	Process  string // the program that was touching it
}

// LoggedExclusion is an exclusion that Defender's own log shows being
// added, and not removed since.
type LoggedExclusion struct {
	When time.Time
	Exclusion
}

// Volume is a drive and whether it is encrypted.
type Volume struct {
	Drive     string
	Encrypted Answer
	State     string // Windows' own wording, such as "On" or "Encrypting"
}

// Account is a member of the Administrators group.
type Account struct {
	Name     string
	Group    bool   // a group of accounts, not one account
	Disabled Answer // the account is switched off
	BuiltIn  string // "Administrator" or "Guest" for the two accounts every PC has
}

// HostsEntry is one working line of the hosts file: a name and the address
// the PC is told to use for it.
type HostsEntry struct {
	Address string
	Names   []string
}

// Installed is a program listed under Apps in Settings.
type Installed struct {
	Name      string
	Publisher string
	Location  string
}

// Guard is everything gathered about how the PC is protected and who can
// get into it.
type Guard struct {
	Antivirus        []SecurityProduct
	AntivirusHealth  Answer // Windows Security's own verdict: yes for good
	FirewallHealth   Answer
	FirewallProducts []SecurityProduct
	Firewall         []FirewallProfile

	RealTime          Answer // Microsoft Defender checks files as they are opened
	Tamper            Answer // Defender's settings are locked against other programs
	Exclusions        []Exclusion
	ExclusionsVisible bool // the list of exclusions could be read

	// What Defender's own log says. The log can be read without
	// administrator rights, and reaches back as far as Windows has kept it.
	HistoryRead      bool
	HistoryDays      int               // how many days back the look went
	Detections       []Detection       // newest first
	LoggedExclusions []LoggedExclusion // oldest first
	SwitchedOff      []time.Time       // when real-time protection was switched off, newest first

	UAC         Answer // Windows asks before a program gets administrator rights
	UACSilent   Answer // ... but lets administrators through without asking
	Build       string // the version of Windows, such as 22H2 (19045.5247)
	LastUpdate  time.Time
	UpdateKnown bool
	Volumes     []Volume
	SecureBoot  Answer

	RemoteDesktop Answer
	RemoteNLA     Answer // Remote Desktop asks for a password before showing the sign-in screen
	Admins        []Account
	AdminsVisible bool
	Guest         Answer // the Guest account is switched on
	AutoSignIn    Answer // Windows signs an account in by itself, with a stored password
	AutoUser      string

	HostsPath    string
	Hosts        []HostsEntry
	HostsVisible bool
	Programs     []Installed
}

// Fault is an error a piece of hardware reported about itself, or one
// Windows met while using a disk.
type Fault struct {
	When  time.Time
	Fatal bool   // Windows could not put it right
	Part  string // which part reported it, in plain words: "the processor", "the memory"
	Where string // which one of that part, when the record says: a processor's number, a disk
	Words string // the record in Windows' own words, on one line
	ID    int    // the number Windows gives this kind of record
}

// Crash is one time Windows stopped with a blue screen.
type Crash struct {
	When time.Time
	Code uint32 // the stop code, such as 0x50
	Name string // its name, such as PAGE_FAULT_IN_NONPAGED_AREA, when known
}

// Wipe is one time a Windows log was cleared.
type Wipe struct {
	When time.Time
	Log  string // which log
	By   string // the account that did it
}

// Drive is a fixed disk drive and how full it is.
type Drive struct {
	Letter     string // such as C:
	Size, Free uint64 // in bytes
}

// Condition is what Windows' own logs say about the PC's hardware and
// about Windows stopping, and how full the disks are.
type Condition struct {
	Read      bool        // the log could be read
	Days      int         // how many days back the look went
	Hardware  []Fault     // newest first
	Crashes   []Crash     // newest first
	PowerCuts []time.Time // times the PC went off without shutting down and without a blue screen
	Disk      []Fault     // faults on a disk itself
	Retries   int         // times a disk had to be asked twice, which also happens when a USB drive is pulled out
	Wiped     []Wipe
	Drives    []Drive
	Started   time.Time // when Windows last started
}

// Gap is something that could not be read, so that the report can say so
// plainly instead of leaving it out.
type Gap struct {
	Area Area
	What string
}

// Withheld ends a sentence about something the look could not read. Without
// administrator rights that is the reason. With them, Windows itself keeps
// the thing from everyone, and saying "needs administrator rights" would
// send the reader after rights they already have.
func Withheld(elevated, several bool) string {
	switch {
	case !elevated:
		return "can only be read with administrator rights"
	case several:
		return "are protected by Windows and cannot be read even with administrator rights"
	}
	return "is protected by Windows and cannot be read even with administrator rights"
}

// Fingerprint returns the fingerprint of a file, if the look worked it out.
func (s *Snapshot) Fingerprint(path string) string {
	if s == nil || path == "" {
		return ""
	}
	return s.Fingerprints[strings.ToLower(path)]
}

// Folders are the places on this PC that the rules need to know by name.
type Folders struct {
	Windows         string // C:\Windows
	System          string // C:\Windows\System32
	ProgramFiles    string
	ProgramFilesX86 string
	ProgramData     string
	Users           string // C:\Users
	Profile         string // C:\Users\name
	Temp            string
	Downloads       string
}

// Snapshot is one look at a PC.
type Snapshot struct {
	Taken    time.Time
	Took     time.Duration
	Computer string
	User     string
	Windows  string // such as Windows 10 Pro 22H2
	Elevated bool   // the look was taken with administrator rights
	Folders  Folders

	Startup     []Startup
	Processes   []Process
	Connections []Connection
	Guard       Guard
	Condition   Condition
	Gaps        []Gap

	// Fingerprints holds the SHA-256 fingerprint of the files that findings
	// are about, by the file's path in small letters. A fingerprint is a
	// number worked out from every byte of a file: two files with the same
	// fingerprint are the same file.
	Fingerprints map[string]string
}
