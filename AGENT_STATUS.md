# AGENT_STATUS — LazaScope (deutscher Fork)

**Stand:** 2026-11-28. **Quelle:** Fork von `kimineechan/LazaScope` (MIT), Branch `main`.

## Ziel

Deutsche Oberfläche für LazaScope, ohne das Verhalten zu ändern: alle sichtbaren Texte
übersetzt, Sprache über `--lang de` / `LAZASCOPE_LANG=de` / Windows-Sprache, sonst Englisch.

## Aufbau der Übersetzung

- `internal/i18n/i18n.go` — `T(text)`, `Set(lang)`, `System()`, `FromArgs`, `Init`.
- `internal/i18n/de.json` — englischer Text als Schlüssel, deutscher als Wert (eingebettet
  mit `go:embed`).
- Aufrufe: jeder sichtbare Text geht durch `i18n.T("...")`. Fehlt ein Eintrag, erscheint der
  englische Text (kein Fehler).
- Sprachwahl: `--lang de` (GUI und CLI), `LAZASCOPE_LANG`, sonst `GetUserDefaultUILanguage`.
- Zusammengesetzte Texte: Fragmente einzeln durch `i18n.T`; Texte mit Zahlen als Formatstrings
  (`fmt.Sprintf(i18n.T("%d ..."), n)`).
- `const`-Deklarationen mit `i18n.T` mussten zu `var`/`:=` werden (sonst „not constant");

## Stand

- **760** Einträge in `de.json`.
- Deutsch: Navigation, Übersicht, Seitentitel, Spaltenköpfe, Fakten, Regel-Titel, alle
  „Warum"-Erklärungen, Regel-Hinweise, CLI-Ausgaben, die meisten Oberflächentexte.
- Englisch bleiben: Produktnamen (Wallets, VirusTotal), MITRE-ATT&CK-Techniknamen,
  Dateinamen-Vorlagen und wenige Sonderfälle mit Nullzeichen in Dateifiltern.
- Build: `go build ./...` grün. Tests: alle grün außer `internal/virustotal` (Testserver
  brauchen Loopback-Sockets; in dieser Umgebung gesperrt, nicht durch die Übersetzung).

## Belege

- `go build ./...` Exit 0; `go vet ./cmd/... ./internal/winui` Exit 0.
- GUI mit `--demo --lang de`: Übersicht vollständig deutsch (Screenshot geprüft).
- CLI mit `--demo`: Bereichsnamen deutsch; die übrigen Zeilen hängen an den übersetzten
  Regeln.

## Offen

- Wenige UI-Sonderfälle (Dateifilter mit `\x00`, Dateinamen-Vorlagen) bleiben englisch.
- Ein Pull-Request an `kimineechan/LazaScope` ist nicht gestellt; der Fork ist eigenständig.
- Kein Release im Fork angelegt.
