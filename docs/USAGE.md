# LazaScope usage guide

A portable Windows application that **shows what a PC is doing and points out anything worth a second look**. It reads what starts by itself, what is running, what is talking to the network, how the PC is protected and how its hardware is holding up. It changes nothing.

## Start here

1. Extract the ZIP to a folder on your PC.
2. Open `LazaScope.exe`.
3. LazaScope looks at the PC straight away. This takes a few seconds, and the line at the foot of the window says what it is doing.

The window has no title bar from Windows. Drag it by its top part, around the name, and use the two buttons at its top right corner to minimise or close it. With the keyboard, **Tab** moves from control to control, **Enter** or **Space** presses, the arrow keys move through a list or scroll the box of details, and **Ctrl + Tab** changes section.

The app targets **64-bit Windows 10 and Windows 11**. You do not need Go, Node, Python or an installer. Nothing is uploaded unless you ask: looking a file up on VirusTotal sends its fingerprint, never the file.

The programs are not code-signed. The first time, Windows SmartScreen may say it does not recognise the app: choose **More info**, then **Run anyway**. On Windows 11, where Smart App Control is switched on, Windows may refuse to open LazaScope at all, as Smart App Control has no way to allow one program.

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

With a VirusTotal key of your own saved, **Look up file...** fetches VirusTotal's answer into the details instead, and pressed again offers the page. See [VirusTotal](#virustotal).

Looking files up on VirusTotal is the only thing in LazaScope that reaches the internet, and it never happens unless you ask.

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
| Web page (`.html`) | Reading, printing, or sending to someone who is helping you. It looks like LazaScope's window, opens in any browser, holds no scripts and loads nothing from the internet. Printed, it comes out dark on white |
| Plain text (`.txt`) | Pasting into a message or a forum post |
| Data (`.json`) | Other tools, and **Compare with a report...**. It holds the findings and, under `facts`, every start-up entry, running program, connection, protection setting and health record as it was read. Each finding has a `ref` that names the fact it is about |

The web page and the text are laid out the same way:

1. **This PC at a glance:** which PC, when, and the six lights of the Overview.
2. **What is worth a second look:** everything the rules flagged, the most serious first. Findings about the same thing are gathered under it, so a start-up entry flagged for three reasons appears once, with its three reasons, what you can do, and its details. In the web page the details are folded away under **Details**.
3. **What could not be read**, if anything.
4. **Everything LazaScope read:** the lists 02 Protection to 07 Health, named and numbered as in the window. In the web page each list starts closed; open one to see its rows, and select a row to see its details.

If the look was compared or watched, the report says what that showed.

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

## The top of the window

Four things at the top work on every page:

- **The search box** narrows whichever list is on show. Type words to find the rows that mention them, or `field:value` to ask about one thing, such as `kind:service signed:no`, `path:*\Users\*`, `rule:startup-unsigned`, `attack:T1547.001` or `vt:flagged`. Every term must match. `*` stands for anything, a comma gives a choice (`kind:service,driver`), a minus in front leaves out (`-windows:yes`) and quotes keep words together. Type `?` in the box for the full list of fields. A field that does not exist, or a value a field does not take, is named in the status line instead of quietly matching nothing.
- **Analyst mode** ends each row's details with the exact evidence behind it, as an analyst would copy it into a ticket: registry places and task paths, command lines, process numbers, file sizes and times in UTC, SHA-256, the signature's source, signer, catalogue and the number Windows' check returned, version information, the raw answers of the antivirus and of VirusTotal, log records with their event numbers, and each finding's rule and ATT&CK techniques. **Copy details** copies it with the rest.
- **Wallets...** opens the page about cryptocurrency wallets.
- **VirusTotal...** opens the page about VirusTotal.

## MITRE ATT&CK

MITRE ATT&CK is the public catalogue of the methods attackers use, kept by the MITRE Corporation. Each method, called a technique, has a number such as T1547.001. Security teams file what they find under these numbers, so a finding that carries one can be handed to any of them.

Every finding that may be a trace of a technique names it, under its rule. A finding about a start-up entry also names the technique of the way the entry starts: a line in the Run list, a scheduled task, a service. A weakness, such as a disk that is not encrypted, names none. The numbers were checked against ATT&CK version 20.1 on attack.mitre.org.

**Save ATT&CK layer...** on the 08 Worth a look page writes a layer for MITRE's ATT&CK Navigator, the free web page that shows the whole catalogue as a grid. Open the Navigator at mitre-attack.github.io/attack-navigator, choose **Open Existing Layer**, then **Upload from local**, and pick the file. Each technique is coloured by the most pressing finding that names it. The Navigator reads the file inside your browser. The layer names the PC and what was found on it, so read it before you send it to anyone.

## VirusTotal

VirusTotal is a website, owned by Google, that runs each file it is shown through about 70 antivirus engines. With a free VirusTotal key of your own, LazaScope asks it about the programs on the PC and shows the answers in the window.

1. Make a free account at virustotal.com and open the link VirusTotal sends by email.
2. In your account's menu, choose **API key** and copy the key.
3. In LazaScope, press **VirusTotal...**, click in the box, press Ctrl + V and choose **Save key**. LazaScope checks the key by asking about the fingerprint of an empty file, which says nothing about your PC.

Then **Ask VirusTotal now** asks about every program that starts by itself or is running, except Microsoft's own signed files. **Look up file...** on a list asks about one file; pressed again, it offers to open VirusTotal's page. **Also after each look** asks about new programs after every look.

- **Only the fingerprint is sent, never the file.** VirusTotal learns that your account asked about that file.
- **Nothing is sent until you ask.** Without a key, LazaScope never contacts VirusTotal.
- The key is kept in LazaScope's folder inside your own AppData folder, sealed by Windows so that only your Windows account on this PC can open it. **Forget** removes it and every answer.
- A free key allows 4 lookups a minute and 500 a day, for personal use that is not commercial. LazaScope keeps to that pace, and remembers each answer for a week so as not to ask twice.

What the engines say shows in a **VirusTotal** column on the 03 Start-up and 04 Running pages, and in each file's details. When engines flag a program that starts or runs, it is under 08 Worth a look: five or more engines calling it harmful is **Look first**, two to four **Worth a look**, and one, or suspicion alone, **Good to know**. One or two flags on a little-known or home-made program are often false alarms.

The command-line tool asks with `lazascope-cli virustotal`, with the saved key or the environment variable `LAZASCOPE_VIRUSTOTAL_KEY`.

## Wallets

**Wallets...** lists the cryptocurrency wallets LazaScope found: wallet extensions in the browsers, wallet programs, and folders of wallet files in their usual places. It only notes where they are. It never opens a wallet, shows a key or a phrase, or sends anything about them. The page is kept out of saved reports: a list of someone's wallets is not for sending.

- **A fake wallet extension** takes a real wallet's name, then sends the recovery phrase typed into it to a thief. LazaScope compares an extension's number with the ones the wallet's makers publish. It knows MetaMask's and Phantom's for Chrome, Edge, Brave and Vivaldi, and those of several more wallets for Firefox. It never calls an extension a fake for a wallet whose real number it does not know.
- **Test for address swapping** looks for clipboard-stealing malware, which swaps a copied wallet address for the thief's. It copies three made-up addresses, a Bitcoin one, a newer bc1 Bitcoin one and an Ethereum one, for two seconds each and watches whether anything changes them. Their checksums are wrong on purpose, so no wallet would send coins to one, and Windows is told to keep them out of the clipboard history. Afterwards LazaScope puts back the text that was on the clipboard, and says so plainly if it could not. A picture or files on the clipboard cannot be put back, and LazaScope says so before it starts.
- **Check a download...** compares a wallet installer with the fingerprint (SHA-256) its maker publishes. Paste the fingerprint into the box first.
- **Find recovery phrases...** looks for a recovery phrase saved in a file. More on this below.

### Recovery phrases in files

A recovery phrase (or seed phrase) is the 12 to 24 words a wallet gives you to write down when it is made. Whoever has the words has the coins, from anywhere, so a phrase saved in a file can be taken by any program that reads the file. Malware that steals passwords looks for exactly that.

**Find recovery phrases...** says what it will read and asks first. It then reads the text files and documents in the account's Desktop, Documents and Downloads folders and in OneDrive: plain text, Markdown, rich text, Word and LibreOffice documents, and settings files such as `.env`, `.json` and `.ini`. It looks for 12 or more words in a row from the list of 2,048 words that phrases are made from (BIP 39's English list, which Electrum's seeds use too). Numbers and line breaks between the words, as in "1. word 2. word", do not matter.

A run of such words is then checked:

| What LazaScope found | How it shows |
| --- | --- |
| A complete phrase whose own check holds. The last word of a BIP 39 phrase is partly a check on the others, and Electrum builds a check of its own into its seeds. Random words pass one of these checks rarely (about 1 time in 16 for 12 words, and 1 in 216 for Electrum's) | **Look first**, as a recovery phrase or an Electrum seed |
| A run of the words in a file named like a phrase, such as `seed.txt` or `my wallet.docx` | **Look first** |
| A run of the words that could not be confirmed as a phrase | **Worth a look**: open the file and see |
| The word list itself, in its own order, as wallet programs carry it | Listed, with nothing to do |

Program code is kept from passing for a phrase: names such as `canvas.width`, marks such as `=` and `{`, and words repeated the way code repeats them all break a run, while the words of a real phrase are nearly all different. Files kept only in OneDrive are not read, because reading one would download it, and neither are folders of program code such as `node_modules` or files larger than 4 MB. The search stops after 40,000 files and can be stopped at any time with the same button.

LazaScope never shows, keeps or sends the words. Each file found is listed with the line (or, in a document, the paragraph) where the words start, and what to do: if the phrase belongs to a wallet that holds coins, make a new wallet on a device you trust and move the coins into it before deleting the file, because the phrase may have been copied already.

A phrase can still hide where the search does not look: in a photo or a screenshot, a PDF, an email, a password manager, a note app's own storage, or written in another language.

The rules also look at wallet files in a folder OneDrive, Dropbox or iCloud copies, wallet files on a disk that is not encrypted, clipboard history on a PC with a wallet, hosts-file lines that send a cryptocurrency site somewhere else, connections to names built from such a site's name, such as metamask-login.com, and programs that mine cryptocurrency.

## Timeline

**Timeline...** on the Overview puts everything LazaScope can date in one list, newest first, over the last 90 days: programs started and opened, files changed and downloaded, what Defender found and was told, the last update, hardware errors, blue screens, sudden stops, disk faults and cleared logs. The view above the list narrows it to the last day, week or month, or to what is worth a look.

Two of Windows' records say what ran, even after it closed:

- **UserAssist**, what this account opened from the desktop, Explorer and Start, with how often and when last. It needs no administrator rights.
- **BAM**, the Background Activity Moderator, when each program last ran. Only administrators can read it. Only the account's own records are read, even with administrator rights.

A file saved from the internet carries a hidden mark from Windows (its Zone.Identifier) that often names the address it came from. A file's details say where it came from. The address shows in the window only: the saved web page holds no addresses.

## Protections to switch on

**Protections to switch on...** on the Overview lists the protections that come with Windows and Microsoft Defender, whether each is on, what each does and where to switch it on: blocking of potentially unwanted apps, SmartScreen's check of apps and files, Controlled folder access, network protection, cloud-delivered protection, automatic sample submission, memory integrity, Local Security Authority protection and the vulnerable driver blocklist. Defender's settings are read the way PowerShell's Get-MpPreference reads them. When another antivirus is in charge, Defender's own protections do not apply and are not judged. A setting Windows does not record says **Not known**.

Memory integrity, Local Security Authority protection and the vulnerable driver blocklist are judged by what Windows reports working, not only by their settings. Windows 11 switches them on by itself without always writing a setting, and a protection switched on since the last restart is not working yet: LazaScope then says it is off and that a restart starts it. Where its setting alone does not tell, a protection's details say how LazaScope knows.

The same page says how ready the PC is for ransomware. Two things limit the harm: Controlled folder access, and a copy of your files kept somewhere else. LazaScope looks for File History run in the last 30 days, OneDrive's backup of Documents, Desktop and Pictures, and backup programs it knows by name. With neither, it says so under 08 Worth a look.

## Camera and microphone

**Camera and microphone...** on the Overview lists which programs last used the camera and the microphone, and when, from the records behind Windows' privacy settings. A program using one now is noted. A program with no maker's signature that used one in the last 90 days is worth a look.

## Watch programs start

**Watch programs start...** on the Overview lists every program as it starts, with the program that started it and its command line, and checks each against LazaScope's detections: Word starting PowerShell, a command that deletes Windows' backups, a tool of Windows' own fetching a file, and more. Each detection is a few lines of Go with its reason and its ATT&CK technique, listed in [The detections](DETECTIONS.md).

Windows reports new programs once a second, so one that starts and ends within the same second can be missed. The command lines of other accounts' programs are given to administrators only. Nothing is changed and nothing is sent.

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
.\lazascope-cli.exe find "kind:service signed:no"
.\lazascope-cli.exe timeline 7
.\lazascope-cli.exe live 120
.\lazascope-cli.exe attack layer.json
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
| `find <search>` | Runs a search, written as in the search box, over every list. `--details` adds the exact evidence |
| `attack <file.json>` | Writes a layer for MITRE's ATT&CK Navigator. `--coverage` writes the techniques the rules look for instead, with nothing about any PC |
| `virustotal [files or fingerprints]` | Asks VirusTotal about files by fingerprint, or with none named, about the programs that start or run. Needs your own key |
| `wallets` | Lists the cryptocurrency wallets on the PC and what stood out about them |
| `swap-test` | Runs the address-swap test |
| `phrases [folder]...` | Looks for recovery phrases written in files, in the folders named or in Desktop, Documents, Downloads and OneDrive. Prints each file and line, never the words |
| `timeline [days]` | Lists what happened when, newest first (the last 7 days unless told) |
| `protections` | Lists the protections the PC already has, whether each is on, and its backups |
| `devices` | Lists which programs used the camera and the microphone, and when |
| `live [seconds]` | Watches programs start, and checks each against the detections (60 seconds unless told) |
| `detections` | Lists every detection. `--markdown` prints the table in [The detections](DETECTIONS.md) |
| `version` | Prints the version |
| `help` | Prints the list of commands |

A command that is given an option or a file name it does not take says so and does nothing. The tool ends with 0 when it worked, 1 when what it was asked could not be done, 2 when the command itself was wrong, and 3 if it stopped on a fault of its own.

`scan`, `report`, `find`, `attack`, `wallets`, `timeline`, `protections` and `devices` take `--demo` to show the made-up PC.

## Limits

| Limit | Detail |
| --- | --- |
| Not an antivirus | LazaScope shows and explains. It removes nothing and blocks nothing |
| Windows 11 | Made for it, and tested on Windows 10. Where Smart App Control is switched on, Windows may refuse to open LazaScope, which is not code-signed |
| Hidden software | Software that hides inside the core of Windows (a "rootkit") can hide from LazaScope too |
| A clean result | Means that none of the known signs was seen, not that nothing is wrong |
| Start-up places | The ones that matter most, and browser extensions. The rarer places are not read in this version. An account that is not signed in keeps its start-up list in a file that is not opened |
| Signatures | Checked without going online. A certificate this PC has never met can show as not trusted |
| Addresses | Shown by name only where Windows remembers the lookup. Browsers that do their own lookups leave nothing there, so many stay numbers |
| Scripts | Read for a list of things they can be seen to do. A script can hide what it does |
| Health | What Windows wrote in its log. A fault Windows never noticed is not in it, and a cleared log holds nothing from before |
| A watch | Reads once a second. What lives for less than a second can be missed, and what a connection carries is not read. The live watch has the same limit |
| VirusTotal | Needs a free key of your own, and allows 4 lookups a minute. A file VirusTotal has never seen is not a bad sign in itself |
| Wallets | Fake extensions are told apart only for wallets whose real numbers LazaScope knows |
| Recovery phrases | Found in text files and documents only, and only in English. A phrase in a picture, a PDF or another program's own storage is not found |
| One moment | A look is a snapshot. Without a watch, a program that ran and closed a minute earlier is not in it |
| Storage | Nothing is kept, except what you set up: a saved report, and with VirusTotal, the key (sealed for your account) and its answers, in LazaScope's folder inside AppData. Forget on the VirusTotal page removes both |

For the full list of rules, see [The rules](RULES.md). For source builds and development, see [the README](../README.md).
