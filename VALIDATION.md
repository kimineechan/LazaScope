# Validation

## Checks completed on 22 November 2026

Both programs were compiled with Go 1.27.3 for `windows/amd64`, with CGO disabled, and run on Windows 10 Pro 22H2 (build 19045) without administrator rights.

### Automated tests

- **The rules** are tested with made-up PCs. A healthy one, which holds a good many things that look a little odd and are fine, must produce no findings at all. About ninety single changes to it must each produce exactly the findings they should and no others. Roughly a third of those changes are cases that must stay quiet. A further test fails if any rule has no test that makes it fire.
- **Every finding** produced in those tests is checked for its wording: it has a title, a reason and advice, it says which item it is about, and it never uses the word virus or infected. LazaScope reports reasons, not verdicts.
- **The signature checker** is tested on real files: parts of Windows must come out as signed by Microsoft, with at least one of them found through a catalogue; the test program itself, which nobody signed, must come out as not signed; a copy of a signed program with one byte changed must fail; and a copy of a catalogue-signed program under another name must still be recognised, since a catalogue knows a file by its fingerprint and not by its name.
- **Command reading**, which decides which file a start-up entry really runs, is tested on about forty commands: quoted and unquoted paths, paths with spaces, `rundll32`, `regsvr32`, PowerShell with and without a script file, `cmd /c start`, `conhost --headless`, `msiexec` and the forms drivers are recorded in.
- **The pages** that the window and the report share are tested from the facts to the words on the row, and **the report** is tested for being whole in itself: no script, no link, nothing fetched. A start-up entry whose name is written to look like part of a web page must come out as text.
- **The made-up PC** shown by `--demo` goes through the whole program without Windows, and what it flags is fixed in a test.
- **The window toolkit** is tested as in LazaScrub and LazaReplay, with added tests for the scrolling box of details and the three-coloured lights.

### Against Windows' own tools

The lists were compared with what Windows itself reports on the same PC at the same time.

| List | LazaScope | Windows | Result |
| --- | --- | --- | --- |
| Scheduled tasks | 164 | 164 from `schtasks /query` | The same 164 names |
| Automatic services | 82 | 82 from WMI | 81 in both. One is protected, and LazaScope says it could not read it. One is automatic in the registry and not in WMI |
| Registry Run entries | 17 | 17 from `reg query` | The same entries, with the same 8 marked as switched off in Task Manager |
| Startup folder | 1 shortcut | 1 file | The shortcut's target was read correctly |
| Store app start-up tasks | 5 | 5 in the registry | The same, with the same on and off states |
| Running programs | 353 | 354 from `tasklist` | The one more is the idle process, which is not a program and is left out |
| Waiting TCP ports | 37 | 37 from `netstat -ano` | The same |
| Open TCP connections | 90 | 90 from `netstat -ano` | The same |
| UDP ports | 92 | 92 from `netstat -ano` | The same |
| Disk encryption | 3 disks | 3 disks, from Explorer's own property | The same |

Every running program had its file found, also the ones a program without administrator rights cannot open, because Windows will say where a program is by its number alone.

### Signatures

The 365 different files behind the 423 start-up entries were checked in under three seconds, together with everything else. All but one came out as signed, most of them by Microsoft through a catalogue. The one unsigned file is a program built on that PC and set to start with Windows, which is exactly what the rule is for. Without the catalogue lookup, most of the Windows files in that list would have been reported as unsigned.

Apps from the Microsoft Store bring their own catalogue, which is not in Windows' index. LazaScope looks in the app's own folder for it, and the Store apps on the test PC came out as signed.

### Planted items

`cmd/verify` plants seven harmless items that look suspicious, takes a look, and checks what was flagged. Everything it plants belongs to the account that runs it.

| Planted | Flagged as |
| --- | --- |
| A copy of Notepad named `svchost.exe` in the temporary folder, with a line in the `Run` list | Named like a part of Windows but not where Windows keeps it. Starts from a temporary folder |
| A copy of Notepad named `scvhost.exe`, with a line in the `Run` list | The same two, the first for a name one slip from `svchost` |
| An unsigned program in the Downloads folder, with a line in the `Run` list | Starts from a download folder. Not signed |
| A `Run` line that points at a file that does not exist | Points at a file that is no longer there |
| A `Run` line that runs the Command Prompt with its words broken up | Starts a scripting tool with a scrambled command |
| A shortcut in the Startup folder to the unsigned program | Starts from a download folder. Not signed |
| A copy of the Command Prompt named `lsass.exe`, running from the temporary folder | A running program named like a part of Windows. Running from a temporary folder |

All twelve expected flags were raised and no unexpected one. The program then removed every item and checked that none was left, and the `Run` list, the folders and the Startup folder were checked again by hand.

Settings that belong to the whole PC were not changed for testing: antivirus, firewall, User Account Control, the hosts file, services and the sign-in settings. The rules for those are tested with made-up data.

### False alarms

A normal PC must come out quiet, or nobody will trust the flags. On the test PC, which is in daily use with about 110 installed programs, LazaScope raised six findings, each checked by hand. What they were is left out of this public record, as they describe a PC in daily use.

**False alarms: none.** Each of the six is a real instance of what its rule describes, and each is harmless, which is why the wording is "worth a look" and not more.

### Faults these checks found

- The planted-items check found that `echo`, a word the Command Prompt carries out itself, was taken for a program of the same name that a developer tool had put on the search path. The unsigned `echo.exe` was then reported as the file doing the work. LazaScope now knows the Command Prompt's own words, and searches the folders Windows itself would, not the ones it happened to be started with.
- Reading the start-up list by eye found one scheduled task reported as pointing at a missing file named `\d`. The task runs `rundll32.exe /d library.dll`, and the switch had been read as the library.
- The number that is published for the property Explorer uses to show disk encryption gave no answer on the test PC. LazaScope now asks Windows for the property by its name.
- In the window, the list that shows only what is not part of Windows hid a flagged entry whose command ran PowerShell, which is part of Windows. A flagged row is now kept by every way of narrowing a list.

### Nothing leaves the PC

Neither program links Go's networking packages: `go list -deps` on both shows no `net`, `net/http` or `crypto/tls`. The signature check is made with Windows' own function, with online checks switched off and only what Windows already holds on disk allowed. The report is one file with no scripts and no links.

### Interface

The seven sections were exercised on Windows 10 at 100% display scaling and drawn again at 128%, with the made-up PC and with the real one: every section button, every way of narrowing a list, choosing rows, the state while the first look is still running, and saving a report through the Save dialog. The mouse wheel is tested through the window's own message handling. The screenshots in `docs/screenshots` are of the made-up PC.

## GitHub checks

The included workflow runs the platform-neutral tests on Linux with the race detector, builds both programs on Windows, runs all the tests and the planted-items check there, checks that the committed icon and resources match what `tools/mkres` generates, and packages a ZIP with SHA-256 checksums. A version tag publishes the release only after both jobs succeed.

## Where the testing stops

- Tested on one PC, with Windows 10 in English. It was not run on Windows 11, on a PC joined to a work domain, or on Windows in another language.
- It was not run with administrator rights. What it then reads in addition (Defender's exclusions, other accounts' command lines, protected services) has not been seen working.
- It was not tried against real malware. The planted items imitate the signs, not the behaviour.
- The rules for antivirus, firewall, the hosts file, Defender's exclusions, Remote Desktop, the Guest account, automatic sign-in, debugger settings, `AppInit_DLLs`, the sign-in settings, a changed signature and an unsigned program waiting for connections were tested with made-up data only. On the test PC all of those were in their normal state, so only the normal state was read from a real PC.
- No PC with another antivirus than Microsoft Defender was available, and disk encryption was read on one PC only.
- The start-up list was compared with Windows' own tools, not with Sysinternals Autoruns, which lists many more places than LazaScope reads.
- Two buttons were not pressed in testing. **Copy details** replaces whatever is on the clipboard of the PC in use, and Windows gives a program no clipboard of its own to practise on, so its test only runs when asked for (`LAZASCOPE_TEST_CLIPBOARD=1`). **Show in folder** opens an Explorer window. Both use the same few Windows calls as LazaScrub and LazaBinder.
- The window draws its own controls, so a screen reader cannot read them. The command-line tool and the report give the same information as text.
- The dialogs for saving a file, and the boxes that report an error, are the standard ones of Windows and are not dark.
- A look is one moment. Whether LazaScope keeps up with a PC that is changing fast was not measured.
