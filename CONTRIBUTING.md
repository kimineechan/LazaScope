# Contributing

Thanks for helping improve LazaScope.

## Report a problem

Use the bug-report form and include the Windows version, the LazaScope version, the section of the window and the steps to reproduce. Quote any error text.

The two most useful reports are:

- **A false alarm:** something ordinary that LazaScope flagged. Give the name of the rule, which is shown at the foot of every finding, and say what the program is and where it is installed.
- **A miss:** something LazaScope should have flagged or listed and did not. Say where Windows records it, for example the registry key or the name of the scheduled task.

**Do not paste a whole report into a public issue.** A report names your PC, your account, the programs you run and the addresses they talk to. Copy only the rows that matter, and replace your account name.

For feature requests, describe what you were trying to find out about a PC.

## Develop

Install Go 1.25 or newer. The repository has no third-party Go modules.

Tests that run on any platform:

```sh
go test ./internal/...
```

Format Go changes with `gofmt`. On Windows, run `build.cmd` before submitting a change. It regenerates the resources, runs `go vet` and all the tests, builds both programs and runs `cmd/verify`.

`cmd/verify` plants eleven harmless items in your own account (lines in your `Run` and `RunOnce` lists, files in your temporary and Downloads folders, a shortcut and a batch file in your Startup folder and two waiting programs), checks that ten are flagged for the right reason and the eleventh is left alone, and removes them again. It touches nothing outside your account and needs no administrator rights.

### Layout

| Path | Contents |
| --- | --- |
| `internal/model` | The plain facts about a PC that everything else passes around. No calls to Windows |
| `internal/startup`, `procs`, `netconn`, `protect`, `health` | The collectors: one for each kind of fact. They only read |
| `internal/eventlog` | Reads Windows' own logs |
| `internal/browsers` | Reads the extensions out of the browsers' own record files |
| `internal/scripts` | Reads a script as text and says what it can be seen to do. No calls to Windows |
| `internal/compare` | Holds one look against another, for a saved report and for a watch. No calls to Windows |
| `internal/cmdline` | Follows a command line to the file that does the work |
| `internal/sigcheck` | Who signed a file, in the file or in a catalogue, with a memory of the answers |
| `internal/files` | Looks each file up once: whether it exists, what it says of itself, who signed it |
| `internal/rules` | The rules: plain functions over the facts, each with its reason and advice |
| `internal/scan` | Runs the collectors and ties what they found together |
| `internal/view` | Lays the facts and findings out as the pages that the window and the report both show |
| `internal/report` | The report as a web page, as text and as JSON |
| `internal/sample` | The made-up PC shown by `--demo` |
| `internal/reg`, `com`, `services`, `pcinfo`, `sysdll`, `winpath` | Small helpers: reading the registry, calling Windows components, loading Windows' own DLLs safely |
| `internal/winui` | The window: the drawing code and the controls, shared in form with LazaScrub and LazaReplay |
| `cmd/lazascope` | The app |
| `cmd/lazascope-cli`, `cmd/verify` | The command-line tool and the planted-items check |
| `tools/mkres` | Draws the icon and builds the Windows resource object |

`internal/sigcheck`, `internal/rules`, `internal/scripts` and `internal/compare` must not depend on the window or on each other's insides. They are meant to be used by other programs.

Three tests read the PC they run on and print what they find, to compare by eye with Windows' own tools. They run only when asked for:

```powershell
$env:LAZASCOPE_LIVE = '1'
go test ./internal/eventlog ./internal/netconn -run TestLive -v
```

An antivirus may stop `cmd/verify`, because planting start-up entries is what an antivirus watches for. `go run ./cmd/verify --clean` plants nothing and removes whatever an interrupted run left.

### Rules for a rule

- A rule is a plain function over a `model.Snapshot`. It must not call Windows, read a file or keep anything between calls.
- It gives a title, a reason and advice in plain English, and says which item it is about.
- **It never gives a verdict.** No "virus", no "infected", no "malicious". It says what was seen and why that matters. A test enforces this.
- Add it to the table in `internal/rules/rules_test.go` with at least one change that makes it fire and at least one look-alike case that must stay quiet. A test fails if a rule cannot be made to fire.
- A normal PC must come out quiet. If a rule would fire on ordinary software, narrow it until it does not, and write down in `docs/RULES.md` what it leaves alone.
- Regenerate the table in `docs/RULES.md` with `lazascope-cli rules --markdown`.

### Rules for a detection

- A detection in `internal/detect` looks at one program starting: its name, its file, its command line and the program that started it. It reads nothing else.
- Give it a title, a reason a person can follow, and the ATT&CK technique it stands for, checked on attack.mitre.org.
- Add a case to `detect_test.go` that makes it fire, and one for the honest command most like it, which must stay quiet.
- Print the table again with `lazascope-cli detections --markdown` and put it in `docs/DETECTIONS.md`. A test checks that the two agree.

### Rules for a collector

- **Read only.** Nothing in LazaScope itself may write to the registry, to a file it did not create as a report, or to any setting. The only writing is in `cmd/verify`, in the current account, and it is undone at once.
- Ask for the least access that works, and no administrator rights.
- What cannot be read is returned as a gap with a plain sentence, never silently left out.
- Call a Windows component only through functions that read. Where a table of functions also holds ones that change something, do not use a place next to one.
- No network calls. The one exception is `internal/virustotal`, which a user switches on with a key of their own, and a test fails the build if any other package imports Go's network packages.
- Load Windows' own DLLs through `internal/sysdll`, by their full path.

To regenerate the icon and resources after changing the design, the manifest or `VERSION`:

```sh
go run ./tools/mkres
```

Commit the regenerated `assets/lazascope.ico` and `cmd/lazascope/resources_windows_amd64.syso`.

## Pull requests

Keep a pull request focused. Explain the problem, the resulting behaviour, and the checks performed. Add tests when a change affects a rule, a collector or the reading of commands.

## Releases

Update `VERSION`, `CHANGELOG.md`, and `docs/releases/v<version>.md` together, regenerate the resources, and push the matching `v<version>` tag. The release workflow builds on Windows, runs the tests and the planted-items check, packages both programs, and publishes the ZIP and checksums after the Linux and Windows jobs pass.

See [the publishing guide](docs/GITHUB.md).
