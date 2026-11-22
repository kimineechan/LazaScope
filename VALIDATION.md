# Validation

## Checks completed on 22 November 2026

Both programs were compiled with Go 1.27.3 for `windows/amd64`, with CGO disabled, and run on Windows 10 Pro 22H2 (build 19045) without administrator rights.

Both were then built a second time from nothing, with Go's cache of earlier work ignored (`go build -a`). The two builds of each program are byte for byte the same, which rules out a build spoiled by the PC it was made on.

### Automated tests

- **The rules** are tested with made-up PCs. A healthy one, which holds a good many things that look a little odd and are fine, must produce no findings at all. A hundred single changes to it must each produce exactly the findings they should and no others. A quarter of those changes are cases that must stay quiet. A further test fails if any of the 31 rules has no test that makes it fire.
- **Every finding** produced in those tests is checked for its wording: it has a title, a reason and advice, it says which item it is about, and it never uses the word virus or infected. LazaScope reports reasons, not verdicts.
- **The signature checker** is tested on real files: parts of Windows must come out as signed by Microsoft, with at least one of them found through a catalogue; the test program itself, which nobody signed, must come out as not signed; a copy of a signed program with one byte changed must fail; and a copy of a catalogue-signed program under another name must still be recognised, since a catalogue knows a file by its fingerprint and not by its name.
- **Command reading**, which decides which file a start-up entry really runs, is tested on about forty commands: quoted and unquoted paths, paths with spaces, `rundll32`, `regsvr32`, PowerShell with and without a script file, `cmd /c start`, `conhost --headless`, `msiexec` and the forms drivers are recorded in.
- **The pages** that the window and the report share are tested from the facts to the words on the row. One test holds the overview to the lists: the number it gives for what is not part of Windows must be the number of rows the list shows under the view of that name.
- **The report** is tested for being whole in itself: no script, no link, nothing fetched. A start-up entry whose name is written to look like part of a web page must come out as text. The data form is tested field by field, and a file name that does not end in `.html`, `.txt` or `.json` must be refused before anything is written.
- **The made-up PC** shown by `--demo` goes through the whole program without Windows, and what it flags is fixed in a test.
- **A fault inside LazaScope** while it reads one part of the PC must not close the program. A test makes a reader fail half way and checks that the look carries on and that the part is reported as not read.
- **The window toolkit** is tested as in LazaScrub and LazaReplay, with added tests for the scrolling box of details and the three-coloured lights. The views that narrow a list, and the count beside them, have tests of their own.

### Against Windows' own tools

Each list was compared, entry for entry, with what Windows itself reports on the same PC at the same moment: PowerShell's own commands for programs, tasks, services, drivers and start-up entries, and `netstat -ano` for the network.

| List | LazaScope | Windows | Entry for entry |
| --- | --- | --- | --- |
| Running programs | 316 | 318 | 314 in both. The others are the comparison's own short-lived tools, started between the two readings |
| The same, file of each program | | | The same for 162. Windows gave no answer for 148 that LazaScope found. 1 differs only in how the path is written |
| The same, command line | | | The same for 163, different for none. LazaScope read 7 that Windows' command did not give |
| The same, which program started it | | | Different for none |
| TCP ports waited on | 37 | 37 | The same lines, none on one side only |
| TCP connections in use | 69 | 69 | The same |
| TCP connections opening or closing | 2 | 2 | The same |
| UDP ports | 97 | 97 | The same |
| Scheduled tasks | 164 | 164 | The same names. On or off differs for none. What each task runs is the same for all 164 |
| Automatic services | 81 | 81 | 80 in both. One is protected, and LazaScope says it could not read it. One Windows reports with an unknown start setting. Running or not, and the file, differ for none |
| Drivers that start by themselves | 101 | 100 | The same 100, with the same file and the same running state. The one more is a protected driver Windows' command leaves out |
| Run entries and Startup folder | 18 | 16 | The same 16, with the same commands. The two more are in the 32-bit Run list, which the Windows command used does not read |
| Disk encryption | 3 disks | 3 disks | The same, from Explorer's own property |

Every running program had its file found, also the ones a program without administrator rights cannot open, because Windows will say where a program is by its number alone.

### Signatures

The 373 different program files behind the start-up entries and the running programs were checked in under three seconds, together with everything else. 278 of them are parts of Windows, most of them signed through a catalogue. Without the catalogue lookup, those would have been reported as unsigned.

A sample of 165 of the files, taking every file that is not Windows' own and a spread of those that are, was given to PowerShell's own check (`Get-AuthenticodeSignature`) for a second opinion.

| | Files |
| --- | --- |
| Same verdict from both | 162 |
| LazaScope says signed, PowerShell says not signed | 3 |
| LazaScope says not signed, PowerShell says signed | 0 |

The three are programs of apps from the Microsoft Store. A Store app brings its own catalogue, which is not in Windows' index. LazaScope looks in the app's own folder for it and PowerShell does not.

For 18 of the files the two name a different signer, and for 53 a different place. These are files that carry two signatures, one inside the file from its maker and one in a Windows catalogue. PowerShell reports the catalogue, LazaScope the one inside the file, because that one names who made it.

### Planted items

`cmd/verify` plants eleven harmless items, takes a look, and checks what was said about each. Ten look suspicious and must be flagged. The eleventh does not, and must be listed and left alone. Everything it plants belongs to the account that runs it.

| Planted | Flagged as |
| --- | --- |
| A copy of Notepad named `svchost.exe` in the temporary folder, with a line in the `Run` list | Named like a part of Windows but not where Windows keeps it. Starts from a temporary folder |
| A copy of Notepad named `scvhost.exe`, with a line in the `Run` list | The same two, the first for a name one slip from `svchost` |
| An unsigned program in the Downloads folder, with a line in the `Run` list | Starts from a download folder. Not signed |
| The same program, with a line in the `RunOnce` list | The same two |
| A `Run` line that points at a file that does not exist | Points at a file that is no longer there |
| A `Run` line that runs the Command Prompt with its words broken up | Starts a scripting tool with a scrambled command |
| A shortcut in the Startup folder to the unsigned program | Starts from a download folder. Not signed |
| A batch file in the Startup folder | Starts a script by itself |
| A copy of the Command Prompt named `lsass.exe`, running from the temporary folder | A running program named like a part of Windows. Running from a temporary folder |
| The unsigned program, running from the Downloads folder | Running from a download folder |
| A `Run` line for the real Notepad, in the Windows folder | Nothing, as it should be |

All sixteen expected flags were raised and no unexpected one. The program also checks that looking changed nothing it had planted, then removes every item and checks that none is left. The `Run` and `RunOnce` lists, the folders, the Startup folder and the running programs were checked again by hand after each run, including after a run that was stopped by a fault in the check itself.

Settings that belong to the whole PC were not changed for testing: antivirus, firewall, User Account Control, the hosts file, services and the sign-in settings. The rules for those are tested with made-up data.

### False alarms

A normal PC must come out quiet, or nobody will trust the flags. On the test PC, which is in daily use with about 110 installed programs, LazaScope raised five findings, each checked by hand. What they were is left out of this public record, as they describe a PC in daily use.

**False alarms: none.** Each of the five is a real instance of what its rule describes, and each is harmless, which is why the wording is "worth a look" and not more. While a test tool was running from the temporary folder, a sixth appeared for it, also true.

### Faults these checks found

- The planted-items check found that `echo`, a word the Command Prompt carries out itself, was taken for a program of the same name that a developer tool had put on the search path. The unsigned `echo.exe` was then reported as the file doing the work. LazaScope now knows the Command Prompt's own words, and searches the folders Windows itself would, not the ones it happened to be started with.
- Reading the start-up list by eye found one scheduled task reported as pointing at a missing file named `\d`. The task runs `rundll32.exe /d library.dll`, and the switch had been read as the library.
- The number that is published for the property Explorer uses to show disk encryption gave no answer on the test PC. LazaScope now asks Windows for the property by its name.
- In the window, the list that shows only what is not part of Windows hid a flagged entry whose command ran PowerShell, which is part of Windows. A flagged row is now kept by every way of narrowing a list, and the count beside the list says so.
- The comparison with Windows found 51 drivers listed as starting by themselves that Windows did not list. Windows comes with drivers for disk controllers a PC may not have. They are recorded as loading at boot, and beside that record Windows keeps an override that says "not on this hardware". LazaScope now reads the override, as Windows does.
- The signature comparison found parts of Windows that were not counted as parts of Windows, because they carry a second signature in the name "Microsoft Corporation" and that was the one reported. They are now counted by where they are and who signed them, under either name.
- Planting a batch file in the Startup folder found that nothing flagged it. A script is not a program, so the rule for unsigned programs passed it by. A rule for scripts that start by themselves was added.
- Reading the overview against the lists found that it gave 67 start-up entries as not part of Windows where the list showed 80. The overview left out entries that are switched off and entries that name no file. Both now count the same way.
- Reading the saved reports found that the plain-text form left a cell empty for a task that names no file, so the line ended as if something had been cut off.
- The planted-items check failed once with nothing wrong: it compared two lists of what it had planted whose order was not fixed. It now compares them in a fixed order.
- A report saved under a name with another ending, such as `.pdf`, was written as a web page inside a file that would not open. Such a name is now refused, with a sentence that says which endings are taken.

### Nothing leaves the PC

Neither program links Go's networking packages: `go list -deps` on both shows no `net`, `net/http` or `crypto/tls`. The signature check is made with Windows' own function, with online checks switched off and only what Windows already holds on disk allowed. The report is one file with no scripts and no links.

### Interface

The window was driven through its own message handling, off the visible screen, with the made-up PC and with the real one, and a picture of each state was looked at.

- **Sizes.** At 70% (the smallest it goes, for a screen about 600 pixels high), 87% (a 1366 by 768 screen), 100% and 128% (the largest that fits a 1920 by 1080 screen). The first pass at 70% found "Good to know" cut short in a column and one button with no room to spare. Both were widened.
- **Every section** and every row of the overview's five Open buttons.
- **Every view** of the three lists that have them, including views that match nothing, which say so in words.
- **Look again**, which takes a fresh look.
- **Save report** in all three forms through the Save window, and with a name it must refuse.
- **Show in folder** with no row chosen, with a row that is not about a file, and with a row that is: the first two say why nothing opens, the third opened the right folder.
- **The keyboard alone**: Tab to a button and Space to press it, the arrow keys, Home and End in a list.
- **Minimise and restore.**
- **The state before the first look comes back**, in which every list says that it is still looking.

The mouse wheel is tested through the window's own message handling. The screenshots in `docs/screenshots` are of the made-up PC.

### The saved report

The made-up PC's report was read from the first line to the last in its plain-text form. The real PC's report was read in full down to the long lists, and those lists were read by a script in all three forms of the report, looking for anything a reader would trip over: a row with the wrong number of cells, an empty cell, a leftover of formatting, a date that was never filled in, a count that does not match what it counts, a finding that points at a fact that is not there. After the fix for the empty cell it found nothing.

## GitHub checks

The included workflow runs the platform-neutral tests on Linux with the race detector, builds both programs on Windows, runs all the tests and the planted-items check there, checks that the committed icon and resources match what `tools/mkres` generates, and packages a ZIP with SHA-256 checksums. A version tag publishes the release only after both jobs succeed.

## Where the testing stops

- Tested on one PC, with Windows 10 in English. It was not run on Windows 11, on a PC joined to a work domain, or on Windows in another language.
- It was not run with administrator rights. What it then reads in addition (Defender's exclusions, other accounts' command lines, protected services) has not been seen working, and neither has the button that starts it again with those rights.
- It was not tried against real malware. The planted items imitate the signs, not the behaviour.
- The rules for antivirus, firewall, the hosts file, Defender's exclusions, Remote Desktop, the Guest account, automatic sign-in, debugger settings, `AppInit_DLLs`, the sign-in settings, a changed signature and an unsigned program waiting for connections were tested with made-up data only. On the test PC all of those were in their normal state, so only the normal state was read from a real PC.
- No PC with another antivirus than Microsoft Defender was available, and disk encryption was read on one PC only.
- The start-up list was compared with Windows' own tools, not with Sysinternals Autoruns, which lists many more places than LazaScope reads.
- **Copy details** was not pressed. It replaces whatever is on the clipboard of the PC in use, and Windows gives a program no clipboard of its own to practise on, so its test only runs when asked for (`LAZASCOPE_TEST_CLIPBOARD=1`). It uses the same few Windows calls as LazaScrub and LazaBinder.
- LazaScope checks signatures on programs only. A script can carry one too, and almost none does. A signed script is treated like any other script.
- The window draws its own controls, so a screen reader cannot read them. The command-line tool and the report give the same information as text.
- The dialogs for saving a file, and the boxes that report an error, are the standard ones of Windows and are not dark.
- A look is one moment. Whether LazaScope keeps up with a PC that is changing fast was not measured.
