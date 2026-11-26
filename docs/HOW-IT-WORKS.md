# How LazaScope works

This page is for readers who want the detail: where each fact comes from, how the program is put together, and where it stops. For what the program is and how to use it, see the [README](../README.md) and the [usage guide](USAGE.md).

## Where each fact comes from

LazaScope does not include, download or run Microsoft's Sysinternals tools or any other program. It asks Windows directly, through the same interfaces those tools use.

- **Start-up:** the registry's `Run` and `RunOnce` lists for the PC, for the account, and for the other accounts whose settings are loaded, as 64-bit and as 32-bit programs see them; both Startup folders; the start-up tasks of Store apps; every scheduled task; services and drivers set to start automatically; the sign-in settings `Shell` and `Userinit`; debugger settings; and `AppInit_DLLs`. It also reads Task Manager's on and off switches, so its list matches the Start-up tab. Each command is followed to the file that does the work: for `rundll32.exe thing.dll,Start` that is the library, not `rundll32`, and for a service inside `svchost.exe` it is the service's own library.
- **Browser extensions:** read from the browsers' own record files (Chrome, Edge, Brave, Vivaldi, Opera and Firefox), which are opened for reading. No browser is started.
- **Running programs:** the path, command line, parent, account and start time of each, and the services inside each host program.
- **Connections:** Windows' own table of TCP and UDP connections and waiting ports, with the program that owns each. Names come from Windows' note of recent lookups, the one `ipconfig /displaydns` shows. LazaScope makes no lookup of its own.
- **Protection:** Windows Security's verdict on antivirus and firewall, Microsoft Defender's settings and exclusions, User Account Control, the last installed update, disk encryption, Secure Boot, Remote Desktop, the Administrators group, the hosts file, the name servers and proxy in use, and the installed apps.
- **Windows' own logs:** the System log for hardware errors, blue screens, disk faults and cleared logs, and Microsoft Defender's log for what it found and how its settings changed.
- **Scripts:** a script that starts by itself is opened and read as text, up to 2 MB. It is never run.
- **Signatures:** Windows' own signature check, for a signature inside the file and for one in a catalogue. Many of Windows' own files carry no signature inside them; their fingerprints are listed in signed catalogues instead. A check that skips the catalogues calls most of Windows unsigned, so LazaScope looks in both places, and remembers each answer.
- **The antivirus:** through AMSI, Windows' doorway for programs to hand content to the installed antivirus and ask. AMSI gives no name for what it found, so the name is read from Defender's log.
- **What ran:** UserAssist from the account's own settings, and with administrator rights BAM, for this account only. The download mark (Zone.Identifier) on each file looked at.
- **Defender's settings:** through Windows Management Instrumentation (WMI), as PowerShell's `Get-MpPreference` reads them.
- **Memory integrity, Local Security Authority protection and the driver blocklist:** by what Windows reports working, not only by their settings, as Windows 11 switches them on by itself without always writing a setting, and a setting changed since the last restart has not yet taken effect. Memory integrity comes from Windows' Device Guard report through WMI, the one System Information shows. Local Security Authority protection comes from the note Wininit writes in the System log when it starts LSASS as a protected process, which is how Microsoft says to check; the note is looked for after LSASS's own start, so Fast Startup, which resumes Windows without starting LSASS again, does not mislead it. The vulnerable driver blocklist is on by default since Windows 11 22H2, and memory integrity applies it on every version.
- **Camera and microphone:** the records behind Windows' privacy settings, for this account.
- **Wallets:** wallet extensions from the browsers' record files, wallet programs among those running, and whether the usual folders of wallet files exist. No wallet file is opened.
- **Recovery phrases:** only when asked. The text files and documents in the account's Desktop, Documents, Downloads and OneDrive folders, read as text. The words are checked in memory and never kept, shown or written.
- **New programs, live:** reported once a second by WMI while the live watch runs.
- **VirusTotal:** only with a key of your own, and only when you ask: a file's fingerprint, over a secure connection, with no redirect followed.

## How the program is put together

LazaScope is written in Go using only the standard library and Windows' own interfaces. There are no third-party modules. The window is drawn by the program itself with Win32 calls, without a web view or an interface toolkit.

**Collectors** read facts from Windows: one each for start-up entries, running programs, connections, protection and the health of the PC, and smaller ones for the timeline, the wallets and the camera. A fault inside one collector does not end the look. That part is left out, its light on the Overview shows a ring, and the page says that it could not be read and why.

**The signature checker** asks Windows who signed each file the collectors found. It remembers each answer, which is why a few hundred files take a second or two.

**The rules** are plain functions over the collected facts. They call nothing and read nothing, so each one is tested with made-up PCs, including the cases where it must stay quiet. A rule returns a finding with a title, the reason, what to do, the evidence, and the MITRE ATT&CK techniques it may be a trace of. There are 61 of them, listed in [The rules](RULES.md).

**The detections** of the live watch are written as code too: each is a few lines in `internal/detect` that look at one program starting, with its reason, its ATT&CK technique, a test that makes it fire and one that keeps it quiet on the honest command most like it. There are 15, listed in [The detections](DETECTIONS.md).

**The pages** are built once from the facts and the findings, and the window, the saved reports and the command-line tool all show the same pages.

**One package reaches the network:** `internal/virustotal`, and only with a key the user set up. A test reads every source file and fails if any other package imports Go's network packages.

The signature checker, the rules, the script reader and the detections know nothing of the window, so other tools can reuse them.

## The recovery-phrase finder

A recovery phrase is made of words from a public list of 2,048 (BIP 39's English list, which Electrum's seeds use too). The finder reads a file as text and looks for 12 or more of those words in a row; numbers, punctuation and line breaks between them do not matter. Within a run it looks for complete phrases:

- **BIP 39:** a phrase of n words carries 11 bits a word, and the last n/3 bits are the start of the SHA-256 of the rest. Random words pass about 1 time in 16 for 12 words and 1 in 256 for 24.
- **Electrum:** the HMAC-SHA512 of the phrase, keyed with `Seed version`, starts with the seed's version in hexadecimal (`01`, `100`, `101` or `102`). Random words pass about 1 time in 216.

To keep ordinary text and program code from passing by chance, a run must be made up of its phrases, with at most three other words for each, the words of a phrase must be nearly all different, and the marks of code (`=`, `{`, names such as `canvas.width`) break a run. The word list itself, in its own order, is recognised and left alone. A file whose name points to a phrase (`seed.txt`, `my wallet.docx`) with a run of the words counts as a likely phrase.

## Limits

- **LazaScope is not an antivirus, and it removes nothing.** It shows what is there and what is unusual. Acting on it is up to you.
- **It cannot see software that hides inside the core of Windows** (a "rootkit"). Such software can hide from every program that asks Windows what is running, and LazaScope is one of those.
- **A clean result is not proof that nothing is wrong.** LazaScope only knows the signs it was taught.
- It covers the start-up places that matter most, and browser extensions. Windows has well over a hundred such places, and the rarer ones are not read in this version.
- Without administrator rights it cannot read the list of folders Defender skips, the scheduled tasks Windows shows to administrators only, the start-up lists of other accounts, the command lines of programs that run as other accounts, or a few protected services. It says so on the page where each belongs. **Look again as administrator** reads these too.
- The live watch and **Watch for a minute** see the PC once a second, so a program that lives for less than a second can be missed. LazaScope sees that a connection exists, not what is said over it.
- The health page reports what Windows wrote in its log. A fault Windows never noticed is not in it, and a cleared log holds nothing from before.
- A script is read for a list of things it can be seen to do. A script can hide what it does, so an empty list is not a clean bill.
- Signatures are checked without going online. A certificate this PC has never met can show as not trusted, and a certificate withdrawn after signing is not noticed.
- An address has a name only where Windows remembers the lookup. Browsers that do their own lookups leave nothing there, so many addresses stay numbers.
- Fake wallet extensions are told apart only for wallets whose real numbers LazaScope knows: MetaMask and Phantom in Chrome, Edge, Brave and Vivaldi, and several more in Firefox. Opera's store is not covered.
- Recovery phrases are found in text files and documents, in English. A phrase in a picture, a PDF, an email or another program's own storage is not found. Electrum's seeds from before version 2.0 are not recognised.
- Prefetch, Windows' third record of what ran, is not read in this version.
- The Wallets page, the timeline and the camera and microphone list stay in the window. They are not put into saved reports, which are made to be sent.
- Tested on Windows 10 with Microsoft Defender. See [VALIDATION.md](../VALIDATION.md) for what was checked and where the checking stops.
- The programs are not code-signed, so Windows SmartScreen may ask for confirmation the first time. For the same reason LazaScope would flag a copy of itself set to start with Windows.
- On Windows 11, where Smart App Control is switched on, Windows may refuse to open LazaScope at all. Smart App Control blocks programs that are not code-signed unless Microsoft's cloud service already knows them, and it has no way to allow one program.
