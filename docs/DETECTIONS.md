# The detections

The live watch (Watch programs start... on the Overview, or `lazascope-cli live`) checks every program as it starts against the detections on this page. Each detection is a few lines of plain Go in `internal/detect/detect.go`, with a reason, the MITRE ATT&CK technique it stands for, and a test in `internal/detect/detect_test.go` that makes it fire on what it is written for and stay quiet on the honest commands that look most like it.

**A detection is a reason to look, not a verdict.** Installers make scheduled tasks, management tools encode PowerShell commands, and people download programs every day. The detection says what was seen and why attackers do the same.

## How the watch sees programs

Windows Management Instrumentation (WMI), the part of Windows that answers questions about the system, reports each new process. It needs no administrator rights. WMI looks once a second, so a program that starts and ends within the same second can be missed, and it gives the command lines of other accounts' programs to administrators only. Nothing on the PC is changed and nothing is sent anywhere.

## Every detection

The technique numbers were checked on attack.mitre.org on 24 November 2026, against ATT&CK version 20.1.

| Detection | Usually | What it catches | Why it matters | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| `office-starts-shell` | Look first | An Office program started a command tool | Word, Excel and the other Office programs have no reason to start PowerShell, the command prompt or a script host. A document whose macro does so is the most common way malware gets in through email. | T1204.002 User Execution: Malicious File; T1059 Command and Scripting Interpreter |
| `powershell-encoded` | Worth a look | PowerShell was handed an encoded command | An encoded command is a long run of letters and digits that hides what PowerShell is told to do. Some management tools use it; so does a great deal of malware. | T1027.010 Obfuscated Files or Information: Command Obfuscation; T1059.001 Command and Scripting Interpreter: PowerShell |
| `tool-downloads` | Worth a look | A tool of Windows' own was used to download something | certutil, bitsadmin and PowerShell can fetch files from the internet. Attackers use them because they are signed by Microsoft and seldom blocked. | T1105 Ingress Tool Transfer |
| `certutil-decode` | Worth a look | certutil was used to decode a file | certutil is a certificate tool. Its -decode switch turns text back into a program, a known way to bring a program past filters as harmless-looking text. | T1140 Deobfuscate/Decode Files or Information |
| `mshta-remote` | Look first | mshta ran a script from the internet or from its command line | mshta runs HTML applications. Pointed at a web address, or handed a script directly, it runs that script with the user's rights, past most controls. | T1218.005 System Binary Proxy Execution: Mshta |
| `regsvr32-scriptlet` | Look first | regsvr32 was told to run a script | regsvr32 registers program parts. Given /i: with a web address or scrobj.dll, it fetches and runs a script instead, a trick known as Squiblydoo. | T1218.010 System Binary Proxy Execution: Regsvr32 |
| `rundll32-script` | Look first | rundll32 was told to run a script | rundll32 starts functions inside program libraries. Handed javascript: or mshtml's RunHTMLApplication, it runs a script instead. | T1218.011 System Binary Proxy Execution: Rundll32 |
| `backups-deleted` | Look first | A command deleted Windows' backup copies or recovery | Ransomware deletes the copies Windows keeps of files (shadow copies) and switches off recovery before it locks the files, so that they cannot be got back. Almost nothing else does. | T1490 Inhibit System Recovery |
| `account-created` | Look first | A command made an account, or made one an administrator | Attackers add an account of their own, or raise one to administrator, so that they can come back. | T1136.001 Create Account: Local Account |
| `task-created` | Good to know | A command set up a scheduled task | A scheduled task starts a program at set times or at sign-in. Installers make them, and so does malware that wants to stay. | T1053.005 Scheduled Task/Job: Scheduled Task |
| `run-key-added` | Worth a look | A command added a program to the registry's Run list | A line in the registry's Run list starts a program at every sign-in. Adding one from the command line is a quick way to stay on a PC. | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder; T1112 Modify Registry |
| `defender-changed` | Look first | A command switched off part of Defender, or told it to skip a place | Malware tells the antivirus to skip its folder, or switches parts of it off, before doing anything else. | T1685 Disable or Modify Tools |
| `lsass-dump` | Look first | A command copied the memory of the part of Windows that holds passwords | lsass.exe holds the passwords of signed-in accounts in its memory. Copying that memory out, with ProcDump or a function in comsvcs.dll, is how attackers take them. | T1003.001 OS Credential Dumping: LSASS Memory |
| `wmic-process` | Worth a look | wmic was used to start a program | wmic process call create starts a program through Windows Management Instrumentation, which hides who started it. Attackers use it to move about and to run things quietly. | T1047 Windows Management Instrumentation |
| `started-from-downloads` | Good to know | A program started from a temporary or download folder | Installers and portable tools often run from Downloads. So does malware that was just fetched, before it settles somewhere else. | T1204.002 User Execution: Malicious File |
