# Publish LazaScope on GitHub

## Repository settings

| Setting | Value |
| --- | --- |
| Owner | `kimineechan` |
| Name | `LazaScope` |
| Visibility | Public |
| Default branch | `main` |
| Licence | MIT |
| First release tag | `v1.0.0` |
| First release title | `LazaScope v1.0.0` |

**Description**

```text
Portable Windows utility that shows what a PC is doing (start-up items, running programs, connections, protections) and explains anything worth a second look in plain English. Read-only.
```

**Topics**

```text
windows, golang, desktop-app, security, security-tools, autoruns, process-monitor, digital-signature, incident-response, triage, portable-applications, win32, windows-utilities
```

These settings are also stored in `.github/repository.json` for reference. GitHub does not apply that file automatically.

## How a release is made

A release is built and published by GitHub Actions when a version tag is pushed. You do not need Go installed to publish one.

1. Change `VERSION`, add an entry to `CHANGELOG.md` with the date, and create `docs/releases/v<version>.md`.
2. If you have Go installed, run `go run ./tools/mkres` so the version shown in the EXE's properties matches, and commit the changed resource file. The Windows build checks this and fails if it was forgotten.
3. Commit and push `main`.
4. Create and push the matching version tag:

```powershell
git tag -a v1.0.1 -m "LazaScope v1.0.1"
git push origin v1.0.1
```

The tag must match `VERSION`. Each tagged release uses the source at that tag. Use a new version instead of moving an existing release tag.

The **Build and release** workflow then:

1. Runs the platform-neutral tests on Linux with the race detector.
2. Builds both programs on Windows, runs all the tests and the planted-items check there, and packages the ZIP with its SHA-256 checksums.
3. Publishes the ZIP and `SHA256SUMS.txt` as a release, using `docs/releases/v<version>.md` as the notes, after both jobs pass.

Follow the run under the repository's **Actions** tab. The release appears under **Releases** when it finishes.

If the workflow fails, open the failing job in Actions, fix the error, and push again. If the tag itself points at a broken commit, fix the problem and release the next patch version. A rerun after an already-published release does not overwrite it.

## Publish without the tag

To push changes without making a release, commit and push `main` only. The workflow still builds and tests every push, and keeps the built ZIP as a workflow artifact for 14 days.

## Before the first push

Check that nothing in the repository names a real person or a real PC:

- The screenshots in `docs/screenshots` must be of the made-up PC (`LazaScope.exe --demo`).
- No report from a real PC belongs in the repository.
- Commits are made as `kimineechan` with the GitHub no-reply address.
