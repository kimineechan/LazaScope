# LazaScope usage guide

A portable Windows application that **shows what a PC is doing and points out anything worth a second look**. It reads what starts by itself, what is running, what is talking to the network and how the PC is protected. It changes nothing.

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

Five lights, one for each area.

| Light | Meaning |
| --- | --- |
| Green | Nothing in this area stands out |
| Amber | Something is worth a look |
| Red | Something should be looked at first |
| A ring | This area could not be read |

Beside each light is a count of what was flagged and a line of plain facts, such as "Antivirus on. Firewall on. Last update 9 days ago." **Open** goes to that area's list.

- **Look again** reads the PC afresh.
- **Look again as administrator** starts LazaScope again with administrator rights, after Windows asks you. See [Administrator rights](#administrator-rights).
- **Save report...** writes everything to one file. See [The report](#the-report).

## 02 to 06: the lists

Each of these sections is a list with a box of details under it.

- Select a row to read what it is, where it is recorded, who made it and, if a rule flagged it, why.
- The first column is coloured: red for **Look first**, amber for **Worth a look**, grey for **Good to know**. On the Protection and Accounts pages a green **OK** means the setting is as it should be, and **Not known** means Windows would not say.
- The list above the table narrows what is shown, and the count beside it says how many rows that leaves. A flagged row is never hidden: under **Not part of Windows**, a part of Windows that a rule flagged stays in the list, and the count says so. When a view matches nothing, the box of details says what that means.
- **Show in folder** opens Explorer at the file the row is about.
- **Copy details** puts the text of the details box on the clipboard.

| Section | What it lists | Ways to narrow it |
| --- | --- | --- |
| 02 Protection | Antivirus, firewall, User Account Control, updates, disk encryption, Secure Boot, the hosts file | |
| 03 Start-up | Everything set to start by itself | Not part of Windows, Everything, Only what is worth a look, Only what is switched on |
| 04 Running | Every running program, set under the program that started it | Everything as a family tree, Not part of Windows, Only what is worth a look |
| 05 Connections | Each open connection and each port a program waits on | Everything, Connections to the internet, Ports open to the network, Not part of Windows, Only what is worth a look |
| 06 Accounts | Administrator accounts, Guest, automatic sign-in, Remote Desktop, remote-control software | |

### Words used in the lists

| Word | Meaning |
| --- | --- |
| Maker | The name on the file's digital signature, which is a maker's seal that breaks if the file is changed. "Not signed (says X)" means the file has no seal and only claims to come from X |
| Script file | Shown as the maker of a script: a text file of commands, such as a batch file. LazaScope checks signatures on programs only, and scripts almost never carry one |
| Registry Run | A line in the registry, Windows' settings database, that starts a program each time someone signs in |
| Scheduled task | An entry in Task Scheduler, the part of Windows that starts programs at set times or when something happens |
| Service | A background program that Windows starts by itself and keeps running |
| Driver | A part that runs inside Windows itself, usually to work a piece of hardware |
| Off | The entry has been switched off in Task Manager or Task Scheduler, so it does not start |
| Port | A numbered door on the PC. A program "waits on a port" for others to connect to it |
| Reach | How far away the other end of a connection is: this PC only, the local network, or the internet |

The Start-up list opens showing only what is **Not part of Windows**, because Windows itself accounts for most of the several hundred entries on any PC. Choose **Everything** to see them all.

## 07 Worth a look

Everything the rules flagged, the most serious first. Select a row to read:

- what was found,
- why it matters,
- what you can do about it,
- the facts it rests on: the file, the command, the signature, where it is recorded,
- and the name of the rule, so that you can look it up in [The rules](RULES.md).

Under the list, **What could not be read** names everything LazaScope had no access to.

**Worth a look does not mean harmful.** If you recognise the thing and installed it yourself, nothing needs doing.

## The report

**Save report...** writes one file. Choose the kind in the Save dialog.

| Kind | For |
| --- | --- |
| Web page (`.html`) | Reading, printing, or sending to someone who is helping you. It opens in any browser, holds no scripts and loads nothing from the internet |
| Plain text (`.txt`) | Pasting into a message or a forum post |
| Data (`.json`) | Other tools. It holds the findings and, under `facts`, every start-up entry, running program, connection and protection setting as it was read. Each finding has a `ref` that names the fact it is about |

The report starts with the five lights and everything worth a look, then lists every fact LazaScope read. In the web page, select any row to open its details.

**Read the report before you send it.** It names the PC, the account in use, the programs it runs and the addresses they talk to.

To make a report without opening the window, for instance when someone is guiding you over the phone:

```powershell
.\LazaScope.exe --report "C:\Users\you\Desktop\report.html"
```

The ending of the name chooses the kind, as in the Save dialog. A name with any other ending is refused, so that a report never lands in a file that will not open.

## Administrator rights

LazaScope works without administrator rights and never asks for them by itself. Without them, Windows keeps a few things back:

- the list of folders and programs that Microsoft Defender skips,
- the command lines and accounts of programs that run as other accounts,
- a few protected services.

Each page says what it could not read, and **07 Worth a look** lists it all. **Look again as administrator** on the Overview reads these too. Windows asks for your permission first, and if you say no, nothing changes and the line at the foot of the window says so. Once LazaScope has the rights, the button reads **Running as administrator**.

If User Account Control is set to never notify, Windows gives the rights without asking. LazaScope flags that setting under 02 Protection.

With or without administrator rights, LazaScope only reads.

## Command line

`lazascope-cli.exe` runs the same engine from a terminal or a script.

```powershell
.\lazascope-cli.exe scan
.\lazascope-cli.exe scan --details
.\lazascope-cli.exe report report.html
.\lazascope-cli.exe startup --details
.\lazascope-cli.exe sign "C:\Program Files\App\app.exe"
```

| Command | Result |
| --- | --- |
| `scan` | Prints the five lights and everything worth a look, with the reasons. `--details` adds the facts for each finding |
| `report <file>` | Writes the report. The ending of the name chooses the kind: `.html`, `.txt` or `.json` |
| `startup` | Lists everything set to start by itself. `--details` adds the command, the trigger and the account |
| `running` | Lists the running programs as a family tree. `--details` adds the command lines |
| `network` | Lists the connections and the waiting ports |
| `protection` | Shows the protection settings, the administrators and the hosts file |
| `sign <file>...` | Says who signed each file, where the signature was found and whether it holds |
| `rules` | Lists every rule and why it exists. `--markdown` prints the table in [The rules](RULES.md) |
| `version` | Prints the version |
| `help` | Prints the list of commands |

A command that is given an option or a file name it does not take says so and does nothing. The tool ends with 0 when it worked, 1 when what it was asked could not be done, 2 when the command itself was wrong, and 3 if it stopped on a fault of its own.

`scan` and `report` take `--demo` to show the made-up PC. The exit code is 0 on success and 1 when something could not be done.

## Limits

| Limit | Detail |
| --- | --- |
| Not an antivirus | LazaScope shows and explains. It removes nothing and blocks nothing |
| Hidden software | Software that hides inside the core of Windows (a "rootkit") can hide from LazaScope too |
| A clean result | Means that none of the known signs was seen, not that nothing is wrong |
| Start-up places | The dozen that matter most. Browser extensions and the rarer places are not read in this version |
| Signatures | Checked without going online. A certificate this PC has never met can show as not trusted |
| Addresses | Shown as numbers, because looking up their names would mean going online |
| One moment | A look is a snapshot. A program that ran and closed a minute earlier is not in it |
| Storage | Nothing is kept. Close the window and the look is gone, unless you saved a report |

For the full list of rules, see [The rules](RULES.md). For source builds and development, see [the README](../README.md).
