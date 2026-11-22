# Changelog

## 1.0.0 - not yet released

First version.

- An overview page with five lights: Protection, Starts with Windows, Running now, Internet connections, Accounts and remote access.
- List everything set to start by itself: the registry's Run and RunOnce lists for the PC and the account in both the 64-bit and the 32-bit view, the Startup folders, the start-up tasks of Store apps, scheduled tasks, automatic services and drivers, the sign-in settings, debugger settings and AppInit_DLLs, with Task Manager's on and off switches.
- Follow each start-up command to the file that does the work: the library behind `rundll32` and `svchost`, the script behind PowerShell and `wscript`, the program behind `cmd /c start`.
- List the running programs as a family tree, with path, command line, account, start time and the services inside each.
- List the network connections and the ports programs wait on, each with its program and how far its other end is.
- Read the protection of the PC: antivirus and firewall as Windows Security reports them, Microsoft Defender's settings and exclusions, User Account Control, the last installed update, disk encryption, Secure Boot, Remote Desktop, the Administrators group, the hosts file and remote-control software.
- Say who signed every file, looking both inside the file and in Windows' catalogues and the catalogues of Store apps, with a memory so that hundreds of files take seconds.
- Flag what is worth a look with thirty written rules, each with its reason and what to do.
- Save a report as one self-contained web page, as plain text or as JSON.
- Show a made-up PC with `--demo`.
- Include a command-line tool, a check that plants harmless items and confirms each is flagged, Windows build and release automation, and tests.
- Read only, with no network client, and without needing administrator rights.
