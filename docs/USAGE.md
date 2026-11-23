# LazaScope usage guide

A portable Windows application that **shows what a PC is doing and points out anything worth a second look**. It reads what starts by itself, what is running, what is talking to the network, how the PC is protected and how its hardware is holding up. It changes nothing.

## Start here

1. Extract the ZIP to a folder on your PC.
2. Open `LazaScope.exe`.
3. LazaScope looks at the PC straight away. This takes a few seconds, and the line at the foot of the window says what it is doing.

The window has no title bar from Windows. Drag it by its top part, around the name, and use the two buttons at its top right corner to minimise or close it. With the keyboard, **Tab** moves from control to control, **Enter** or **Space** presses, the arrow keys move through a list or scroll the box of details, and **Ctrl + Tab** changes section.

The app targets **64-bit Windows 10 and Windows 11**. You do not need Go, Node, Python or an installer. Nothing is uploaded: the app has no network client.

To see what findings look like without having any, start it with `--demo`. It then shows a made-up PC in place of yours.

```powershell
.\LazaScope.exe --demo
```

## 01 Overview

Six lights, one for each area.

| Light | Meaning |
| --- | --- |
| Green | Nothing in this area stands out |
| Amber | Something is worth a look |
| Red | Something should be looked at first |
| A ring | This area could not be read |

Beside each light is a count of what was flagged and a line of plain facts, such as "Antivirus on. Firewall on. Last update 9 days ago." **Open** goes to that area's list.

- **Look again** reads the PC afresh.
- **Look again as administrator** starts LazaScope again with administrator rights, after Windows asks you. See [Administrator rights](#administrator-rights).
- **Compare with a report...** holds this look against a report you saved earlier. See [What is new](#what-is-new).
- **Watch for a minute** keeps looking for a minute. See [What is new](#what-is-new).
- **Save report...** writes everything to one file. See [The report](#the-report).

## 02 to 07: the lists

Each of these sections is a list with a box of details under it.

- Select a row to read what it is, where it is recorded, who made it and, if a rule flagged it, why.
- The first column is coloured: red for **Look first**, amber for **Worth a look**, grey for **Good to know**. On the Protection, Accounts and Health pages a green **OK** means the setting is as it should be, and **Not known** means Windows would not say.
- The list above the table narrows what is shown, and the count beside it says how many rows that leaves. A flagged row is never hidden: under **Not part of Windows**, a part of Windows that a rule flagged stays in the list, and the count says so. When a view matches nothing, the box of details says what that means.
- **Show in folder** opens Explorer at the file the row is about.
- **Copy details** puts the text of the details box on the clipboard.
- **Look up file...** works out the fingerprint of the file the row is about. See [Look up a file](#look-up-a-file).

| Section | What it lists | Ways to narrow it |
| --- | --- | --- |
| 02 Protection | Antivirus, what Defender found lately, the places Defender skips, firewall, User Account Control, updates, disk encryption, Secure Boot, the hosts file, the name servers and the proxy | |
| 03 Start-up | Everything set to start by itself, and the extensions in each web browser | Not part of Windows, Everything, Only what is worth a look, Only what is switched on, Browser extensions, What is new |
| 04 Running | Every running program, set under the program that started it | Everything as a family tree, Not part of Windows, Only what is worth a look, What is new |
| 05 Connections | Each open connection and each port a program waits on | Everything, Connections to the internet, Ports open to the network, Not part of Windows, Only what is worth a look, What is new |
| 06 Accounts | Administrator accounts, Guest, automatic sign-in, Remote Desktop, remote-control software | |
| 07 Health | Hardware errors, blue-screen crashes, stops without a shutdown, disk faults, cleared logs, and room on each disk | |

### Words used in the lists

| Word | Meaning |
| --- | --- |
| Maker | The name on the file's digital signature, which is a maker's seal that breaks if the file is changed. "Not signed (says X)" means the file has no seal and only claims to come from X |
| Script file | Shown as the maker of a script: a text file of commands, such as a batch file. LazaScope checks signatures on programs only, and scripts almost never carry one |
| Registry Run | A line in the registry, Windows' settings database, that starts a program each time someone signs in |
| Scheduled task | An entry in Task Scheduler, the part of Windows that starts programs at set times or when something happens |
| Service | A background program that Windows starts by itself and keeps running |
| Driver | A part that runs inside Windows itself, usually to work a piece of hardware |
| Browser extension | A small program added to a web browser. It loads whenever that browser is open |
| Off | The entry has been switched off in Task Manager, in Task Scheduler or in the browser, so it does not start |
| New | It was not there in what this look was compared with. See [What is new](#what-is-new) |
| Came and went | It started during a watch and had ended again by the end of it |
| Port | A numbered door on the PC. A program "waits on a port" for others to connect to it |
| Reach | How far away the other end of a connection is: this PC only, the local network, or the internet |
| Fingerprint | A long number (SHA-256) worked out from every byte of a file. Two files with the same fingerprint are the same file |
| Name server (DNS) | The server a PC asks for the address of a website. Whoever runs it sees which sites are looked up |
| Proxy | A go-between that web traffic is handed to and that passes it on |
| Stop code | The number Windows shows on a blue screen, which says in what way it went wrong |

The Start-up list opens showing only what is **Not part of Windows**, because Windows itself accounts for most of the several hundred entries on any PC. Choose **Everything** to see them all.

### Scripts

When something that starts by itself is a script, LazaScope opens the file and reads it as text. The details then say:

- **What the script does, going by its text.** LazaScope looks for the words a script uses to reach the internet, change what starts with Windows, change the antivirus or the firewall, add accounts, delete files, clear logs and the like. This is a reading and not a test: nothing is run. A harmless script can do any of these things, and a script can hide what it does.
- **How it begins.** Its first lines. They are shown in the window only, and are left out of a saved report in case they hold a password.

To read all of a script, open Notepad and drag the file into its window. Do not double-click the file, because that runs it.

### Browser extensions

LazaScope reads the extensions of Chrome, Edge, Firefox, Brave, Vivaldi and Opera from the browsers' own record files. For each it shows the browser and profile, where it came from and what it may do.

| Where it came from | Meaning |
| --- | --- |
| From the browser's store | Added by you from the store, which checks what it hands out |
| Came with the browser | Offered by the browser's maker and installed with it |
| Added from a file | Added by hand from a file, not through a store |
| Loaded from a folder | Loaded from a folder on the PC, which needs the browser's developer mode |
| Added by another program | A program on this PC put it into the browser |
| Forced by a policy | A setting forces it on, and the browser will not let you remove it. Normal at a workplace |
| Loaded by the browser's shortcut | A switch on the line that starts the browser loads it |

Only the first two are left alone by the rules.

### Health

The Health page reads what Windows wrote in its own log over the last 90 days.

- **Hardware errors.** Processors, memory and other parts check themselves, and Windows writes down every error they report, including the ones corrected on the spot. A healthy PC reports none.
- **Blue-screen crashes**, each with its stop code. Different codes from crash to crash are typical of failing hardware. The same code each time more often points at one driver.
- **Stops without a shutdown**: a power cut, an empty battery, a freeze ended with the power button, or overheating.
- **Disk faults**: a disk that can no longer read part of itself, or whose filing system is damaged.
- **Windows logs**: whether one was cleared, which is rare in everyday use.
- **Room on each disk.**

A PC that crashes for no clear reason more often has a worn part than unwanted software, and this page is where that shows.

## 08 Worth a look

Everything the rules flagged, the most serious first. Select a row to read:

- what was found,
- why it matters,
- what you can do about it,
- the facts it rests on: the file and its fingerprint, the command, the signature, where it is recorded,
- and the name of the rule, so that you can look it up in [The rules](RULES.md).

Under the list, **What could not be read** names everything LazaScope had no access to.

**Worth a look does not mean harmful.** If you recognise the thing and installed it yourself, nothing needs doing.

## Look up a file

**Look up file...** is above the Start-up, Running, Connections and Worth a look lists. Select a row first.

1. LazaScope works out the file's fingerprint. Nothing has left the PC at this point.
2. A box shows the fingerprint and asks whether to open VirusTotal's page for it. VirusTotal is a website, owned by Google, that shows what about 70 antivirus products say about a file.
3. On **Yes**, your own web browser opens that page. Only the fingerprint is sent, and it is the browser that sends it. The file itself stays on the PC.
4. On **No**, nothing is sent. The fingerprint stays in the details, where **Copy details** copies it.

If VirusTotal has never seen the file, it says so. That is common for new and home-made programs, and is not a bad sign in itself.

This is the only thing in LazaScope that reaches the internet, and it never happens without your yes.

## What is new

A single look says what is there. It cannot say what has changed, and it misses whatever comes and goes between two looks. Two buttons on the Overview deal with that. Both mark rows as **New** in the lists, where the view **What is new** shows only those.

### Compare with a report...

1. Today, press **Save report...** and choose **Data for other tools (.json)**.
2. Another day, press **Compare with a report...** and choose that file.

LazaScope then marks every start-up entry, browser extension, running program and waiting port that the report did not have, and lists what is gone and what has changed: an entry that now runs something else, an entry that was switched on or off, and fifteen protection settings, among them the antivirus, the firewall, User Account Control, Remote Desktop, the administrator accounts, the places Defender skips, the name servers and the proxy.

A program that happens to be open now and was closed then shows as new. That is true, and usually means nothing. Start with what is new under **03 Start-up**.

### Watch for a minute

Modern malware is often gone within seconds: a program starts, sends what it came for, and ends. A single look never sees it.

**Watch for a minute** takes a look and then reads the list of programs and connections again once a second. Whatever turns up is added to the lists and marked **New**. If it has ended again by the end, it is marked **Came and went**, and stays in the list. Press **Stop watching** to end early.

LazaScope sees that a connection exists and which program opened it. It does not read what is said over it. A program that lives for less than a second can slip between two readings.

## The report

**Save report...** writes one file. Choose the kind in the Save dialog.

| Kind | For |
| --- | --- |
| Web page (`.html`) | Reading, printing, or sending to someone who is helping you. It opens in any browser, holds no scripts and loads nothing from the internet |
| Plain text (`.txt`) | Pasting into a message or a forum post |
| Data (`.json`) | Other tools, and **Compare with a report...**. It holds the findings and, under `facts`, every start-up entry, running program, connection, protection setting and health record as it was read. Each finding has a `ref` that names the fact it is about |

The report starts with the six lights and everything worth a look, then lists every fact LazaScope read. In the web page, select any row to open its details. If the look was compared or watched, the report says what that showed.

**Read the report before you send it.** It names the PC, the account in use, the programs it runs, the browser extensions, and the sites and addresses they talk to. The lines LazaScope copied out of scripts are not in it.

To make a report without opening the window, for instance when someone is guiding you over the phone:

```powershell
.\LazaScope.exe --report "C:\Users\you\Desktop\report.html"
```

The ending of the name chooses the kind, as in the Save dialog. A name with any other ending is refused, so that a report never lands in a file that will not open.

## Administrator rights

LazaScope works without administrator rights and never asks for them by itself. Without them, Windows keeps a few things back:

- the list of folders and programs that Microsoft Defender skips,
- the scheduled tasks that Windows shows to administrators only, usually a few dozen,
- the start-up lists of the accounts that services run as,
- the command lines and accounts of programs that run as other accounts,
- a few protected services.

Each page says what it could not read, and **08 Worth a look** lists it all. **Look again as administrator** on the Overview reads these too. Windows asks for your permission first, and if you say no, nothing changes and the line at the foot of the window says so. Once LazaScope has the rights, the button reads **Running as administrator**.

Two things are read from Windows' own logs and need no rights: what Microsoft Defender found, and the exclusions its log shows being added. So even without administrator rights LazaScope can often say that Defender was told to skip a place, and when.

If User Account Control is set to never notify, Windows gives the rights without asking. LazaScope flags that setting under 02 Protection.

With or without administrator rights, LazaScope only reads.

## Command line

`lazascope-cli.exe` runs the same engine from a terminal or a script.

```powershell
.\lazascope-cli.exe scan
.\lazascope-cli.exe scan --details
.\lazascope-cli.exe report report.html
.\lazascope-cli.exe startup --details
.\lazascope-cli.exe health
.\lazascope-cli.exe compare last-week.json
.\lazascope-cli.exe watch 120
.\lazascope-cli.exe sign "C:\Program Files\App\app.exe"
```

| Command | Result |
| --- | --- |
| `scan` | Prints the six lights and everything worth a look, with the reasons. `--details` adds the facts for each finding, with the fingerprint of each file |
| `report <file>` | Writes the report. The ending of the name chooses the kind: `.html`, `.txt` or `.json` |
| `startup` | Lists everything set to start by itself, and the browser extensions. `--details` adds the command, the trigger and the account |
| `running` | Lists the running programs as a family tree. `--details` adds the command lines |
| `network` | Lists the connections and the waiting ports |
| `protection` | Shows the protection settings, what Defender's log holds, the name servers, the proxy, the administrators and the hosts file |
| `health` | Shows hardware errors, blue screens, disk faults and cleared logs from Windows' own log, and the room on each disk |
| `compare <report.json>` | Takes a look and says what is new, gone or changed since a report saved as data |
| `watch [seconds]` | Keeps looking for that long (60 seconds unless told, at most 600) and lists what came and went |
| `sign <file>...` | Says who signed each file, where the signature was found and whether it holds, and gives the file's fingerprint |
| `rules` | Lists every rule and why it exists. `--markdown` prints the table in [The rules](RULES.md) |
| `version` | Prints the version |
| `help` | Prints the list of commands |

A command that is given an option or a file name it does not take says so and does nothing. The tool ends with 0 when it worked, 1 when what it was asked could not be done, 2 when the command itself was wrong, and 3 if it stopped on a fault of its own.

`scan` and `report` take `--demo` to show the made-up PC.

## Limits

| Limit | Detail |
| --- | --- |
| Not an antivirus | LazaScope shows and explains. It removes nothing and blocks nothing |
| Hidden software | Software that hides inside the core of Windows (a "rootkit") can hide from LazaScope too |
| A clean result | Means that none of the known signs was seen, not that nothing is wrong |
| Start-up places | The ones that matter most, and browser extensions. The rarer places are not read in this version. An account that is not signed in keeps its start-up list in a file that is not opened |
| Signatures | Checked without going online. A certificate this PC has never met can show as not trusted |
| Addresses | Shown by name only where Windows remembers the lookup. Browsers that do their own lookups leave nothing there, so many stay numbers |
| Scripts | Read for a list of things they can be seen to do. A script can hide what it does |
| Health | What Windows wrote in its log. A fault Windows never noticed is not in it, and a cleared log holds nothing from before |
| A watch | Reads once a second. What lives for less than a second can be missed, and what a connection carries is not read |
| One moment | A look is a snapshot. Without a watch, a program that ran and closed a minute earlier is not in it |
| Storage | Nothing is kept. Close the window and the look is gone, unless you saved a report |

For the full list of rules, see [The rules](RULES.md). For source builds and development, see [the README](../README.md).
