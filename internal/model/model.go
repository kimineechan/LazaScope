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

	Opinion Opinion // for a script: what the installed antivirus said when asked about it

	Origin *Origin // where the file came from, when Windows marked it as a download
}

// Origin is the mark Windows puts on a downloaded file (a hidden part of
// the file called Zone.Identifier): which zone it came from and, when the
// program that saved it said so, the address.
type Origin struct {
	Zone     int    // 3 is the internet; 1 the local network, 2 trusted sites, 4 restricted sites
	Host     string // the address it was downloaded from
	Referrer string // the page that led to it
}

// Defence is a protection that Windows or Microsoft Defender has, and
// whether it is switched on.
type Defence struct {
	Key        string // a short name: pua, smartscreen, cfa, network, cloud, samples, hvci, lsa, drivers
	Name       string // its name in Windows Security, such as Controlled folder access
	On         Answer
	Defender   bool   // a part of Microsoft Defender, which stands aside when another antivirus is in charge
	Ransomware bool   // it helps against ransomware
	Note       string // how LazaScope knows, when its setting alone does not tell
}

// Backups is what the PC shows of copies of the account's files.
type Backups struct {
	FileHistory time.Time // when File History last copied the files; zero for never
	OneDrive    []string  // the account's folders that OneDrive copies, such as Documents
	Programs    []string  // backup programs installed
}

// DeviceUse is a program's use of the camera or the microphone, as
// Windows records it for its privacy settings.
type DeviceUse struct {
	Device  string // "camera" or "microphone"
	App     string // a program's path, or the name of an app from the Store
	Program bool   // App is a program file on disk, not an app from the Store
	Allowed Answer // the switch for this app in the privacy settings
	Start   time.Time
	Stop    time.Time
	File    File // for a program, what is known of its file
}

// InUse reports whether the program is using the device now: it started
// and has not stopped since.
func (d DeviceUse) InUse() bool {
	return !d.Start.IsZero() && (d.Stop.IsZero() || d.Stop.Before(d.Start))
}

// Run is a record Windows keeps of a program having been run.
type Run struct {
	Path   string        // the program, or for an app from the Store, its name
	Source string        // "UserAssist": opened by this account from the desktop or Start; "BAM": Windows' record of programs run lately
	Count  int           // how many times, where the record says
	Last   time.Time     // when last
	Focus  time.Duration // how long it was in front, where the record says
}

// Opinion is what the antivirus installed on this PC said when LazaScope
// handed it a script or a hidden command and asked. It is the antivirus's
// judgement, not LazaScope's, and is always shown as such.
type Opinion struct {
	Asked   bool   // the content was handed over, and the antivirus answered
	Harmful bool   // the antivirus calls it harmful
	Name    string // the antivirus's own name for what it found, when its log gives one
}

// Reputation is what VirusTotal said about a file when it was asked by the
// file's fingerprint: what the antivirus engines VirusTotal runs made of
// the file the last time they looked at it. It is their judgement, gathered
// by VirusTotal, and never LazaScope's.
type Reputation struct {
	Asked      time.Time    // when VirusTotal was asked
	Known      bool         // VirusTotal has a report on the file; false when it has never seen it
	Malicious  int          // engines that call it harmful
	Suspicious int          // engines that call it suspicious
	Undetected int          // engines that found nothing
	Harmless   int          // engines that call it harmless
	Analysed   time.Time    // when the engines last looked at it
	Label      string       // VirusTotal's own suggested name for what it is, when it has one
	Names      []EngineName // what the engines that flag it call it
	Votes      int          // the VirusTotal community's score: below zero when people voted it harmful
	Kind       string       // what kind of file VirusTotal says it is, such as Win32 EXE
	KnownAs    string       // the name VirusTotal knows the file by
}

// EngineName is what one antivirus engine on VirusTotal calls a file.
type EngineName struct{ Engine, Name string }

// Engines returns how many engines gave a verdict on the file.
func (r Reputation) Engines() int { return r.Malicious + r.Suspicious + r.Undetected + r.Harmless }

// Flags returns how many engines call the file harmful or suspicious.
func (r Reputation) Flags() int { return r.Malicious + r.Suspicious }

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
	RunKey           StartupKind = iota // a line in the registry's Run list
	RunOnceKey                          // the same, used once and then removed
	StartupFolder                       // a file or shortcut in a Startup folder
	StoreApp                            // an app from the Microsoft Store that asked to start at sign-in
	ScheduledTask                       // a task in Task Scheduler
	Service                             // a background program Windows starts and keeps running
	Driver                              // a part that runs inside Windows itself, usually for hardware
	LogonSetting                        // what Windows runs as a user signs in
	DebuggerSetting                     // a program set to run in place of another
	LoadedLibrary                       // a library pushed into every program that shows a window
	BrowserExtension                    // a small program added to a web browser, which loads whenever the browser is open
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
	case BrowserExtension:
		return "Browser extension"
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
	case BrowserExtension:
		return "A small program added to a web browser. It loads whenever that browser is open, and can be allowed to read and change the pages you visit."
	}
	return ""
}

// ExtensionSource is where a browser extension came from.
type ExtensionSource int

const (
	SourceUnknown ExtensionSource = iota
	FromStore                     // added by the user from the browser's own store
	WithBrowser                   // offered by the browser's maker and installed with it
	FromFile                      // added by hand from a file, not through a store
	Unpacked                      // loaded from a folder, with the browser's developer mode on
	FromOutside                   // put there by another program on the PC
	ByPolicy                      // forced by a policy, as a workplace does
	CommandLine                   // loaded by a switch on the line that starts the browser
)

func (s ExtensionSource) String() string {
	switch s {
	case FromStore:
		return "From the browser's store"
	case WithBrowser:
		return "Came with the browser"
	case FromFile:
		return "Added from a file"
	case Unpacked:
		return "Loaded from a folder"
	case FromOutside:
		return "Added by another program"
	case ByPolicy:
		return "Forced by a policy"
	case CommandLine:
		return "Loaded by the browser's shortcut"
	}
	return "Not known"
}

// Extension is a small program added to a web browser.
type Extension struct {
	Browser   string // such as Google Chrome
	Profile   string // which of the browser's profiles it is in
	ID        string // the extension's own number in the browser
	Name      string
	Version   string
	About     string // what it says of itself
	Enabled   bool
	Source    ExtensionSource
	EverySite bool     // it may read and change the pages of every website
	May       []string // what else it is allowed to do, in plain words
	Folder    string   // where its files are, when the browser says
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

	Extension *Extension // for a browser extension: what the browser records about it

	Said Opinion // what the installed antivirus said about the commands on the entry's line, when they were worth asking about

	New bool // it was not there in the report this look was compared with
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

	Said Opinion // what the installed antivirus said about the commands on its command line, when they were worth asking about

	New   bool      // it started during the watch, or was not running in the report this look was compared with
	Ended bool      // it was seen during the watch and has ended since
	Left  time.Time // when it was last seen, for one that ended
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

	// Names are the names this PC looked up that led to the other end's
	// address, as Windows remembers them. No lookup is made to fill this in.
	Names []string

	New   bool      // it was opened during the watch, or is a waiting port the compared report did not have
	Ended bool      // it was opened during the watch and has closed again
	Seen  time.Time // when it was first seen, for one opened during the watch
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
	Source   string // how Defender came by it, in its own word: "Real-Time Protection", "AMSI" when a program asked, and so on
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

// NameServer is a server this PC asks for the addresses of websites (a
// DNS server). Whoever runs it sees the names of the sites that are looked
// up, and decides which address each name gets.
type NameServer struct {
	Address    string
	Connection string // the network connection it is set for, such as Wi-Fi
	ByHand     bool   // typed in on this PC, not handed out by the network
}

// Proxy is a go-between that this account's web traffic is sent through.
type Proxy struct {
	Read     bool   // the setting could be read
	Server   string // the go-between in use, such as 10.0.0.1:8080; "" when none is switched on
	Script   string // the address of a script that picks the go-between; "" when none is set
	AllUsers bool   // the setting is one for the whole PC
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

	NameServers     []NameServer
	NameServersRead bool
	Proxy           Proxy
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

// Comparison says what a look was held against, and what that showed
// beyond the marks on the lists themselves.
type Comparison struct {
	With    string    // what it was compared with, to finish "compared with ..."
	When    time.Time // when that other look was taken
	Watched bool      // the comparison is a watch: the look was kept up for a while

	NewStartup, NewPrograms, NewDoors, NewConnections int
	Ended                                             int      // programs that started during a watch and ended again
	Gone                                              []string // what was there before and is not now, one line each
	Changed                                           []string // settings that differ, one line each
}

// Wallet is a cryptocurrency wallet found on the PC: an extension in a
// browser, a program, or a folder of wallet files.
type Wallet struct {
	Name     string // the wallet's name, such as MetaMask or Electrum
	Kind     string // "Browser extension", "Program" or "Wallet files"
	Where    string // the browser and profile, or the folder or file
	Verified bool   // an extension whose number is the real wallet's, as its maker publishes it
	Keys     bool   // its files can hold the keys to coins, as a hardware wallet's app does not
	Ref      string // what the look also holds about it, such as startup:12 or process:4410
	Synced   string // the cloud service that copies its folder off the PC, if any
}

// CloudFolder is a folder that a cloud service copies off the PC.
type CloudFolder struct {
	Service string // such as OneDrive or Dropbox
	Path    string
}

// ClipboardSettings is what Windows keeps of what is copied.
type ClipboardSettings struct {
	Read    bool
	History Answer // Windows keeps a history of what was copied, shown with Windows key + V
	Cloud   Answer // ... and sends it to the account's other devices
}

// SwapTest is the outcome of the test for a program that swaps a copied
// wallet address for another, so that coins go to a thief.
type SwapTest struct {
	When    time.Time
	Tried   []string // the kinds of address tried, such as Bitcoin
	Swapped bool
	Kind    string // the kind of address that was swapped
	Into    string // what it was swapped for
	By      string // the program that swapped it, when Windows can say
	PID     uint32
	Path    string
}

// PhraseSearch is the outcome of the search for recovery phrases written
// down in files. A recovery phrase is the 12 to 24 words that give whoever
// has them a wallet's coins. The search keeps where the words are, never
// the words.
type PhraseSearch struct {
	When    time.Time
	Folders []string // the folders searched
	Read    int      // files read
	Cloud   int      // files not read because they are kept only in the cloud, and reading them would download them
	Big     int      // files not read because they are larger than the search reads
	Locked  int      // files and folders that could not be opened
	Full    bool     // the search stopped at its limit of files, so some were not read
	Stopped bool     // the search was stopped before it was done
	Found   []PhraseFile
}

// PhraseFile is a file that holds a run of recovery words.
type PhraseFile struct {
	Path     string
	Runs     int   // how many runs of recovery words it holds
	Lines    []int // the line each run starts on, for the first twenty runs
	Words    int   // the most recovery words in a row, outside the word list itself
	Phrase   int   // the length of the longest complete phrase whose check holds, or 0 for none
	Electrum bool  // that phrase is an Electrum seed, which only Electrum's own check confirms
	Named    bool  // the file's name points to a phrase too, such as "seed" or "wallet"
	List     bool  // every run is the word list itself, in the list's own order: not a phrase
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

	// Engine names the antivirus that was asked about scripts and hidden
	// commands, or is "" when none could be asked.
	Engine string

	// Compared is set when the look was held against an earlier report, or
	// kept up for a while as a watch.
	Compared *Comparison

	// Fingerprints holds the SHA-256 fingerprint of the files that findings
	// are about, by the file's path in small letters. A fingerprint is a
	// number worked out from every byte of a file: two files with the same
	// fingerprint are the same file.
	Fingerprints map[string]string

	// The cryptocurrency side: the wallets found, the folders a cloud service
	// copies, what Windows keeps of the clipboard, and the outcome of the
	// address-swap test, when it was run.
	Wallets []Wallet
	Clouds  []CloudFolder

	// Ran holds the records Windows keeps of programs having been run.
	Ran []Run

	// The defences Windows has, the backups, and the programs that used the
	// camera and the microphone.
	Defences   []Defence
	Backups    Backups
	DeviceUses []DeviceUse

	Clipboard ClipboardSettings
	SwapTest  *SwapTest
	Phrases   *PhraseSearch // set once the search for recovery phrases in files has run

	// VirusTotal holds what VirusTotal said about files, by fingerprint. It
	// is empty unless the person using LazaScope set up a VirusTotal key of
	// their own and had files looked up.
	VirusTotal map[string]Reputation
}

// Reputation returns what VirusTotal said about a file, if it was asked.
func (s *Snapshot) Reputation(path string) (Reputation, bool) {
	print := s.Fingerprint(path)
	if print == "" {
		return Reputation{}, false
	}
	r, ok := s.VirusTotal[print]
	return r, ok
}
