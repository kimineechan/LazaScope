# Changelog

## 1.0.0 - not yet released

First version.

- An overview page with six lights: Protection, Starts with Windows, Running now, Internet connections, Accounts and remote access, PC health.
- List everything set to start by itself: the registry's Run and RunOnce lists for the PC and the account in both the 64-bit and the 32-bit view, the Startup folders, the start-up tasks of Store apps, scheduled tasks, automatic services and drivers, the sign-in settings, debugger settings and AppInit_DLLs, with Task Manager's on and off switches.
- Follow each start-up command to the file that does the work: the library behind `rundll32` and `svchost`, the script behind PowerShell and `wscript`, the program behind `cmd /c start`.
- List the running programs as a family tree, with path, command line, account, start time and the services inside each.
- List the network connections and the ports programs wait on, each with its program and how far its other end is.
- Read the protection of the PC: antivirus and firewall as Windows Security reports them, Microsoft Defender's settings and exclusions, User Account Control, the last installed update, disk encryption, Secure Boot, Remote Desktop, the Administrators group, the hosts file and remote-control software.
- Say who signed every file, looking both inside the file and in Windows' catalogues and the catalogues of Store apps, with a memory so that hundreds of files take seconds.
- List the extensions added to Chrome, Edge, Firefox, Brave, Vivaldi and Opera: where each came from and what it may do.
- Read a script that starts by itself as text: what it can be seen to do, and how it begins. The script's own lines stay out of saved reports.
- Read Windows' own logs: errors the hardware reported about itself, blue screens with their stop codes, stops without a shutdown, disk faults, cleared logs, and from Microsoft Defender's log what it found, when its real-time protection was switched off, and the exclusions the log shows being added. None of this needs administrator rights.
- Show the far end of a connection by name where Windows remembers the lookup, without making a lookup.
- Show the name servers (DNS) the PC asks and whether each was typed in, and the proxy setting.
- Give every flagged file a SHA-256 fingerprint, and offer to open VirusTotal's page for any listed file's fingerprint in the user's own browser, on a yes.
- Compare a look with a report saved earlier as data: what is new, what is gone and which of fifteen protection settings have changed.
- Watch for a minute, reading the programs and connections once a second, so that what starts and ends again within seconds is still seen.
- Read the start-up lists of the other accounts whose settings are loaded, and say plainly that Windows hides some scheduled tasks from accounts without administrator rights.
- Flag what is worth a look with sixty-one written rules, each with its reason and what to do.
- Ask the installed antivirus about scripts and hidden commands through Windows' AMSI, and decode PowerShell's encoded commands to read them.
- Name the MITRE ATT&CK techniques each finding may be a trace of, and write layers for MITRE's ATT&CK Navigator.
- A search box over every list, and an analyst mode that adds the exact evidence behind each row.
- VirusTotal's verdicts in the window, with a key of the user's own: fingerprints only, at the pace a free key allows, the key sealed for the user's account.
- Cryptocurrency wallets: the wallets found, fake wallet extensions told apart by their numbers, wallet files left where they can be copied, a test for clipboard-stealing malware, and a check of a wallet download against its published fingerprint.
- Find recovery phrases saved in text files and documents, confirmed by BIP 39's check or Electrum's, and say where each is without ever showing the words. Carries BIP 39's English word list (MIT licence).
- A timeline of what happened when, with where downloaded files came from and Windows' records of what ran (UserAssist, and BAM with administrator rights).
- The protections the PC already has and whether each is on, how ready the PC is for ransomware, and which programs used the camera and the microphone.
- A live watch of programs starting, checked against fifteen detections written as code.
- Save a report as one self-contained web page in the window's dark look, as plain text, or as JSON that carries every fact as it was read, with a reference from each finding to the fact it is about. The web page and the text gather the findings about one thing under it, and keep the long lists in the window's order; the web page keeps them closed until opened.
- Say so in words when something could not be read, when a view of a list matches nothing, and when a fault inside LazaScope stopped one part of a look. The rest of the look carries on.
- Show a made-up PC with `--demo`.
- Include a command-line tool, a check that plants twelve harmless items and confirms that eleven are flagged and one is left alone, Windows build and release automation, and tests.
- Read only, and without needing administrator rights. Nothing reaches the internet unless the user asks a file to be looked up on VirusTotal: then its fingerprint is sent, never the file. Only internal/virustotal may reach the network, and a test holds the code to that.
