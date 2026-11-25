# Validation

## Checks completed on 25 November 2026

The fifth round added the recovery-phrase finder, on the same PC (Windows 10 Pro 22H2, build 19045). The full automated tests pass and `go vet` is clean.

### The word list

BIP 39's English list was downloaded from the Bitcoin BIPs repository on GitHub (`bip-0039/english.txt`), with the owner's yes. It holds 2,048 words in alphabetical order, each of 3 to 8 small letters, and no two start with the same four letters. A test pins its SHA-256 (`2f5eed53...b24dbda`), and Git is told to keep the file byte for byte, so a copy with changed line endings cannot slip in. BIP 39 is under the MIT licence, which is in `THIRD-PARTY-NOTICES.txt`.

### How the finder was checked

- **The checks of a phrase.** BIP 39's check was tested on the published test vectors (Trezor's, nine of them in English) and on phrases of every length made in the test by a second, separate implementation. Electrum's check was tested on four seeds from Electrum's own tests, one of each kind (standard, SegWit, two-factor, two-factor SegWit), each of which gave exactly the version number Electrum gives it. Altered phrases fail: a word changed, two swapped, one short, one too many.
- **Reading files.** Plain text in UTF-8 and UTF-16 (with and without the mark Notepad writes), rich text, Word and LibreOffice documents. The documents were made by LibreOffice itself from the same text, and each named the right paragraph.
- **Planted files.** A folder of twelve files, every phrase in it a published test phrase: a numbered phrase, a UTF-16 file, a 24-word phrase in a `.env` file, two Electrum seeds (one in a file named like one, one not), the three documents, twelve list words that are not a phrase, the word list as JSON, a phrase in program code and one in `node_modules` (both rightly not read), ordinary writing, and a file marked as kept only in the cloud (counted, and not read). Every one came out as it should, from the terminal.
- **This PC.** The search read 1,782 files in the account's Desktop, Documents, Downloads and OneDrive folders: 21 seconds the first time, under 2 seconds once Windows had the folders in memory.
- **The window.** The question before the search, the search, the message after it and the rows on the Wallets page, on this PC and on the made-up one. **Stop the search** was pressed during two searches, which stopped after 234 and 331 files and said that not every file was read.
- **Linux.** GitHub's core job runs the tests on Linux, which had never been tried. The 22 core packages with tests were built for Linux here and run in Ubuntu under WSL: all pass.

### Faults found while building this round

- **Program code passed for a phrase.** The first version flagged three lines of JavaScript in saved web pages (`canvas.width !== client.width ...`, where one 12-word stretch of a longer run passed BIP 39's check by chance) and ten runs of program code in Markdown notes. A phrase must now make up its run, with at most three other words each, and its words must be nearly all different, as random words are and code is not. Names in code such as `canvas.width` and marks such as `=` and `{` break a run. Over the same 1,782 files, none of the thirteen false alarms remains.
- **Electrum's seeds were only worth a look.** Electrum uses the same words with a check of its own, which LazaScope now knows.
- The history package's tests did not build on Linux (a live test called a Windows-only function), and the browsers package's tests judge Windows paths, which Linux joins differently. Both now run on Windows only.
- A document's place was called a line; it is now a paragraph. A column was cut short, and a message said "1 file(s)".

### The saved report

The web page was given the look of the window: its colours, its lights and its lettering, on a dark sheet that turns dark on white when printed. Findings about the same thing are now gathered under it, the long lists follow the window's sections and start closed, and the text report follows the same order.

- **How it was checked.** The tests hold the order of the lists, that nothing starts open, that an item flagged three times shows its facts and its way of switching off once, that two hardware errors in the same minute stay two, and that the page still holds no script, link or address. The made-up PC's report was read in full in all three forms. This PC's report was searched by a script for formatting faults, empty values, dates that were never filled in, doubled words and garbled letters, and none were found. The web page was looked at in Edge at full width, at the width of a phone (500 pixels, the narrowest window Edge makes without a screen) and with the print style.
- **Faults found in the reports, all fixed.** The lists came in another order than the window's sections, and under three kinds of names. An item flagged for several reasons repeated all its facts each time. Two facts gave dates as numbers where the rest of the report uses words. "Is not encrypted (off)" said the same thing twice, and "These protections are on this PC and switched off" read as on and off at once. The data form wrote apostrophes and the > sign as escape codes.

### Where the fifth round stops

- A phrase in a picture, a PDF, an email, a password manager or a note app's own storage is not found, nor one written in another language's list. Sticky Notes keeps its notes in a database of its own; it has never been used on this PC, so reading it could not be tested, and it is not read.
- Electrum's seeds from before version 2.0 use another word list and carry no check. They are not recognised.
- Tested on Windows 10 only.

## Checks completed on 24 November 2026

The fourth round added the parts below, on Windows 10 Pro 22H2 (build 19045), with and without administrator rights. Each part was tested with made-up data first, then on this PC. The full automated tests pass, `go vet` is clean, and both programs build twice to the same bytes.

### What was added, and how each part was checked

- **Asking the installed antivirus** (AMSI). The standard harmless test line was called harmful and an ordinary line was not, live. The test line is never written into any file: Defender blocked one of LazaScope's own source files the one time it was, so it is put together as the program runs.
- **MITRE ATT&CK.** Every technique number was opened on attack.mitre.org (version 20.1). A test checks that every number a rule names is in the list and that every number in the list is named. Both kinds of layer, the findings of the made-up PC and what the rules look for, were opened in MITRE's ATT&CK Navigator 5.3.2 on its own website with ATT&CK 20.1, and every technique showed in the expected colour. The Navigator read the files in the browser; nothing was sent.
- **Search and analyst mode.** The search language has its own tests, among them every field, choices, wildcards, a minus, quotes, and the errors for a field or a value that does not exist. The search was used in the window and from the terminal on the made-up PC.
- **VirusTotal.** Tested against a stand-in for VirusTotal on this PC: a report read in full, a file never seen, every refusal VirusTotal's documentation lists, the pace of four lookups a minute, a minute's refusal waited out once, stopping, a redirect not followed (so the key goes nowhere else), damaged and oversized answers, and an unreachable network. Then once against the real VirusTotal with a made-up key, which it refused as "Wrong API key", read correctly. The key's seal opens again for this account and not when damaged. A test reads every source file and fails if any package but `internal/virustotal` imports Go's network packages. No real key was used: a live lookup with a key waits for the owner of the PC to set one up.
- **Wallets.** The real numbers of wallet extensions were read from the makers' own download pages (metamask.com, docs.metamask.com, phantom.com), the Edge store and Mozilla's catalogue. The Chrome Web Store could not be read automatically, so brands without a number read from a maker's own page are not judged. The rules have cases for each sign and for the honest look-alikes, such as PhantomBuster, phantomjs.org, finance.yahoo.com and trevor.com.
- **The address-swap test.** The three made-up addresses fail their own checksums, proved in tests with Base58Check, bech32 and EIP-55 (Keccak-256 checked against its known value, and each checker against published examples). With a harmless stand-in for a clipper that swapped only the made-up Ethereum address, the test caught the swap from the terminal and from the window, named the stand-in's process, and put the clipboard back.
- **Timeline and what ran.** UserAssist and BAM are read with made-up records in tests. On this PC, 39 UserAssist records were read without administrator rights; with them, LazaScope read 50 BAM records for this account, the same 50 the registry holds.
- **Protections and camera use.** Defender's settings read through WMI matched `Get-MpPreference` exactly, with and without administrator rights. The camera and microphone records listed the programs the privacy settings show.
- **The live watch.** Fifteen detections, each tested on what it is written for and on the honest command most like it. On this PC, a two-second ping and an encoded two-second PowerShell pause were seen with their command lines, and the pause set off `powershell-encoded`, from the terminal and in the window. A command that ends within a second, such as `schtasks /query`, was not seen, as WMI's once-a-second report says it would be.

### Faults found while building this round

- **The address-swap test lost the clipboard's text once.** The command-line tool's window did not answer the message Windows sends a clipboard's owner when another program empties the clipboard, so the stand-in clipper's swap was held up for three seconds, and the putting back failed without saying so. The test now answers those messages while it waits, keeps trying to put the clipboard back for five seconds, and says plainly when it could not. Every clipboard call now stays on one thread from opening to closing, as Windows requires.
- A file report from VirusTotal names engines and labels that are not LazaScope's to trust: they are kept to one line of limited length before they are shown.
- The saved web page holds no web addresses. VirusTotal's and a download's addresses are marked so that the window shows them and the web page leaves them out.
- The first look at Defender's PUA setting read the registry, which does not always record it; it now reads Defender's own setting through WMI.
- A browser running as many copies flooded the timeline; a program's copies are now one moment.
- The Wallets page said it could not check an extension it had in fact found to be a fake; it now says what was found.

### Planted items

`cmd/verify` now plants twelve items. All twelve came out as they should, were removed, and were checked to be gone, and a further check of the Run lists, the Startup folder, Temp and Downloads found nothing left. Defender quarantined `verify.exe` afterwards, as it has before, and its history holds the test line's entries, named as tests.

### Where the fourth round stops

- A live VirusTotal lookup with a real key, and "Check a download..." with a real wallet installer, wait for the PC's owner.
- The recovery-phrase finder is not built: it needs the public list of 2,048 recovery words, which is not downloaded without the owner's yes. (It was given, and the finder was built on 25 November.)
- Prefetch, the third record of what ran, is not read.
- The comparison of every list with Windows' own tools was done in the third round; this round changed none of those lists and did not repeat it.
- Tested on Windows 10 only, with Microsoft Defender as the antivirus.

## Checks completed on 23 November 2026

A third round, on the same PC: Windows 10 Pro 22H2 (build 19045), this time **both without and with administrator rights**. It added a sixth light and thirteen rules, and it began with the one check the second round had left open.

### With administrator rights

The look was taken with administrator rights and compared, entry for entry, with Windows' own lists taken with the same rights at the same moment.

| What | LazaScope | Windows | Difference |
| --- | --- | --- | --- |
| Running programs | 354 | 353 (`Get-CimInstance Win32_Process`) | 352 in both. The rest are the comparison's own tools and the idle process |
| Command lines | 348 | 333 | The same for all 333 that Windows gave. LazaScope read 15 more, of protected programs. Different for none |
| Accounts | 352 | 334 (`Get-Process -IncludeUserName`) | The same for all 334. LazaScope knew 18 more. Different for none |
| Program files | 347 | 333 | The same for 331. For 2, Windows writes the same path with `\\?\` in front |
| Connections | 255 | 255 (`netstat -ano`, taken before and after) | Every line of LazaScope's is in netstat's. None missing either way |
| Scheduled tasks | 230 | 230 (`Get-ScheduledTask`) | The same names. On and off the same for all |
| Automatic services | 82 | 82 | The same |
| Drivers that start by themselves | 101 | 101 | The same |
| Start-up commands | 20 | 18 (`Win32_StartupCommand`) | All 18 of Windows' are in LazaScope's. The other two are lines for 32-bit programs |
| Name servers | 2 | 2 (`Get-DnsClientServerAddress`) | The same |

Defender's exclusions, the hardware errors and the blue screens were compared the same way and matched. Their numbers are left out of this public record, as they describe a PC in daily use.

The same comparison without administrator rights: programs 351 in both, command lines the same for 202 and different for none, connections 226 of 226, scheduled tasks 164 of 164, services and drivers the same, hardware errors and blue screens the same.

**The button** was pressed: **Look again as administrator** in a window without the rights started a second copy, which a helper with administrator rights confirmed to have them, and the first window closed. The window with the rights was looked at page by page.

### What the first look with administrator rights showed

It found six faults, which are fixed.

1. **66 scheduled tasks were missing, and nothing said so.** Windows shows some tasks to administrators only: 232 with the rights against 166 without. Two of the hidden ones were not Windows' own. A program without the rights cannot count what it is not shown, so the look now says plainly that such tasks exist and are missing.
2. **A task that reads a named script and runs it was called a scrambled command**, at "Look first". Nothing was hidden: the script's file was named on the line. Such a line is now followed to the script, and judged as a script.
3. **With the rights, a thing that still could not be read was said to "need administrator rights".** It now says that Windows protects it from everyone.
4. **A shell that only passes a scrambled command on was flagged beside the tool that runs it**, so one thing was reported twice. The messenger is now left out.
5. **Two start-up lines were missing**: Windows' own list held two for the accounts that services run as. The start-up lists of the other accounts whose settings are loaded are now read.
6. **The saved web page and text report lacked the Health page** and the fingerprints, which the window showed. A test now holds the reports to every page the window has.

### What was added, and how each part was checked

- **A reader for Windows' own logs**, tested on made-up records of each kind and then on this PC: what it found is what `Get-WinEvent` lists, the same number on the same days.
- **PC health.** Six rules, each tested with made-up PCs for when it must fire and when it must stay quiet.
- **What Microsoft Defender's own log holds.** Read without administrator rights, it agreed with what `Get-MpPreference` gives with them.
- **Scripts read as text.** Twenty-three made-up scripts, in PowerShell, batch, JavaScript, Python and VBScript, each with the signs it must and must not show. A test checks that the script's own lines never reach a saved report.
- **Fingerprints.** Checked against the two values published with SHA-256 itself, and on this PC against `certutil -hashfile` for Notepad.
- **Look up file...** was pressed twice, on a flagged file and on one that was not, and answered No both times: the box showed the right file and fingerprint, and nothing was opened. A test holds the address to a fingerprint and nothing else. The address was not opened from LazaScope, so that the browser in use was left alone.
- **Names for addresses.** LazaScope's list was the same as `ipconfig /displaydns`, 12 addresses of 12, at the same moment. A test asks for a name that cannot have been looked up before, with the same switches, and checks that the answer comes at once, is empty, and leaves no trace in Windows' note of lookups. That is the evidence that the question sends nothing.
- **Name servers and proxy.** The same as `Get-DnsClientServerAddress` and the registry on this PC. The two rules were tested with made-up data, because changing either setting to test a rule would change how the PC reaches the internet.
- **Browser extensions.** The extensions LazaScope lists are the ones in the browsers' own records, read a second time by a separate script. The reader is tested on made-up records of every origin a browser distinguishes, and on folders laid out like a PC's.
- **Compare with a report.** A report was saved, one harmless line was put in this account's `Run` list, and the comparison named exactly that line as new. The line was removed and checked to be gone, and the comparison then showed nothing new among what starts.
- **Watch.** During a nine-second watch a harmless program was started that opened one connection and ended. The watch listed the program as started and ended again, with its connection.

### Faults found while building this round

1. A scheduled task that does two things is two entries under one name. The comparison took the second for a change of the first. Everything of one name is now gathered before comparing.
2. Short-lived UDP ports, a different one each time, were counted as new and as gone. They are now left out of a comparison.
3. Asking for remembered names the documented way left out names that Windows learnt over another network connection, so `ipconfig /displaydns` showed 9 addresses where LazaScope showed 3. It now asks the way that tool does, and the two agree.
4. A detection that Defender wrote down twice within moments was listed twice.
5. "Today" was used for something that happened the evening before. Days are now counted on the calendar.
6. At the smallest window size, the count beside the views was cut off by the new button. The views and the count were given more room.

### Planted items

The check ran once more with all forty-four rules: all eleven items came out as they should, were removed, and were checked to be gone. The check now has a way to only clean up (`--clean`), because Microsoft Defender stopped it once on 22 November 2026, as "Behavior:Win32/Persistence.A!ml". Planting start-up entries is what an antivirus watches for. Nothing was left behind that time either.

### What LazaScope flags on this PC now

Nine findings without administrator rights, twelve with them. Each was checked by hand against Windows' own tools, and all are true. What they are is left out of this public record, as they describe a PC in daily use.

### Automated tests, both programs, twice

`go vet` and every test pass. Both programs were built twice, the second time from nothing, and the two builds are byte for byte the same.

### Where the third round stops

- Still one PC, with Windows 10 in English and Microsoft Defender.
- **Look up file...** was never answered Yes, and **Copy details** was never pressed, for the reasons given above and below.
- The rules for a proxy, a typed-in name server, a cleared log, a disk fault, a nearly full disk, sudden stops, and an extension that did not come from a store were tested with made-up data only. This PC has none of those.
- The watch was run for seconds, not for its full ten minutes, and not against anything that tries to hide from it.
- An account that is not signed in keeps its start-up list in a file that LazaScope does not open.
- Whether a scheduled task that Windows hides from administrators as well can be found was not tried.

## Checks completed on 22 November 2026

This is the record of the second round, as it stood that day: five lights and thirty-one rules, without administrator rights.

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

The workflow first ran on GitHub on 25 November 2026, when the repository was published, and passed: the Linux tests in 49 seconds, and the Windows build, tests and planted-items check in 1 minute 39 seconds. It warned that the step that keeps the ZIP used a version of `actions/upload-artifact` that runs on Node.js 20, which GitHub is retiring. The workflow now uses `upload-artifact` v7 and `download-artifact` v8, which run on Node.js 24, and the next run passed with no warning.

The release step first ran for the tag `v1.0.0` on 25 November 2026 and published the release: the Linux tests in 40 seconds, the Windows build, tests and planted-items check in 2 minutes 6 seconds, and the publishing in 11 seconds. The SHA-256 of the published ZIP is the one the packaging step printed. Both programs in it are byte for byte the same as the ones built on the test PC from the same source with Go 1.27.3, so anyone can rebuild them from the source and get exactly the published files.

## Where the testing stopped on 22 November 2026

This is where the first round stopped. Later rounds lifted some of it: the third round ran LazaScope with administrator rights.

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
