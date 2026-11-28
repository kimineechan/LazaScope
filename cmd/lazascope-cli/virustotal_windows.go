//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"lazascope/internal/i18n"
	"os"
	"strings"
	"time"

	"lazascope/internal/files"
	"lazascope/internal/rules"
	"lazascope/internal/scan"
	"lazascope/internal/virustotal"
	"lazascope/internal/winpath"
)

// virusTotalCommand asks VirusTotal about files, by their fingerprints:
// the files or fingerprints named, or with none named, the programs that
// start by themselves or run on this PC. It needs a VirusTotal key of the
// person's own: the one saved in the window, or LAZASCOPE_VIRUSTOTAL_KEY.
func virusTotalCommand(args []string) error {
	key, err := virustotal.Key()
	if errors.Is(err, virustotal.ErrNoKey) {
		return errors.New(i18n.T("there is no VirusTotal key. Save one in LazaScope's window (the VirusTotal... button at the top right), or set LAZASCOPE_VIRUSTOTAL_KEY"))
	}
	if err != nil {
		return err
	}
	client, err := virustotal.New(key)
	if err != nil {
		return err
	}
	path, err := virustotal.MemoryPath()
	if err != nil {
		path = ""
	}
	memory := virustotal.OpenMemory(path)

	type item struct{ name, path, print string }
	var todo []item
	if len(args) == 0 {
		s := scan.Run(scan.Everything, progress)
		for _, c := range virustotal.Candidates(s, scan.Judge(s)) {
			todo = append(todo, item{c.Name, c.Path, ""})
		}
	} else {
		for _, a := range args {
			if print := strings.ToLower(a); virustotal.ValidHash(print) {
				todo = append(todo, item{print, "", print})
			} else {
				todo = append(todo, item{winpath.Base(a), a, ""})
			}
		}
	}
	fmt.Fprintf(os.Stderr, "Asking VirusTotal about %d files, by fingerprint only, at most %d a minute.\n", len(todo), virustotal.PerMinute)
	flagged, unknown := 0, 0
	for i, it := range todo {
		print := it.print
		if print == "" {
			info, err := os.Stat(it.path)
			if err != nil || info.IsDir() {
				fmt.Printf("  %-12s %s: could not be read\n", "-", it.path)
				continue
			}
			var ok bool
			if print, ok = memory.Print(it.path, info.Size(), info.ModTime()); !ok {
				if print, err = files.Fingerprint(it.path); err != nil {
					fmt.Printf("  %-12s %s: %v\n", "-", it.path, err)
					continue
				}
				memory.KeepPrint(it.path, info.Size(), info.ModTime(), print)
			}
		}
		r, ok := memory.Answer(print)
		if !ok || !virustotal.Recent(r, time.Now()) {
			if wait := client.Wait(); wait > 0 {
				fmt.Fprintf(os.Stderr, "  [%d/%d] waiting %d seconds for a turn...\n", i+1, len(todo), int(wait.Round(time.Second)/time.Second))
			}
			if r, err = client.Look(context.Background(), print); err != nil {
				if virustotal.Fatal(err) {
					memory.Save()
					return err
				}
				fmt.Printf("  %-12s %s: %v\n", "-", it.name, err)
				continue
			}
			memory.Keep(print, r)
			memory.Save()
		}
		label := it.name
		if it.path != "" {
			label = it.path
		}
		fmt.Printf("  %-12s %s\n", virustotal.Says(r), label)
		switch {
		case !r.Known:
			unknown++
		case r.Flags() > 0:
			flagged++
			fmt.Printf("               %s.\n", rules.VirusTotalSays(r))
			if r.Label != "" {
				fmt.Printf("               VirusTotal's label: %s\n", r.Label)
			}
			for _, n := range r.Names {
				fmt.Printf("               %s: %s\n", n.Engine, n.Name)
			}
			fmt.Printf("               %s\n", virustotal.Page(print))
		}
	}
	fmt.Printf("\n%d flagged by at least one engine, %d not known to VirusTotal. That is the judgement of the engines VirusTotal runs, not LazaScope's.\n", flagged, unknown)
	return nil
}
