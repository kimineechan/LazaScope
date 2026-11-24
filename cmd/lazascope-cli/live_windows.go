//go:build windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/detect"
	"lazascope/internal/sensor"
)

// liveWatch prints every program that starts, for a while, with the
// detections each sets off. Ctrl+C stops it early.
func liveWatch(seconds string) error {
	span := 60
	if seconds != "" {
		n, err := strconv.Atoi(strings.TrimSpace(seconds))
		if err != nil || n < 1 || n > 3600 {
			return fmt.Errorf("say how many seconds to watch, from 1 to 3600, such as: lazascope-cli live 120")
		}
		span = n
	}
	stop := make(chan struct{})
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	go func() {
		select {
		case <-interrupt:
		case <-time.After(time.Duration(span) * time.Second):
		}
		close(stop)
	}()
	fmt.Fprintf(os.Stderr, "Watching programs start for %d seconds. Ctrl+C stops it. Nothing is changed.\n", span)
	started, alerted := 0, 0
	err := sensor.Watch(stop, func(e detect.Event) {
		started++
		command := e.Command
		if command == "" {
			command = "(command line not given to this account)"
		}
		by := e.By
		if by == "" {
			by = "number " + strconv.Itoa(int(e.Parent))
		}
		fmt.Printf("%s  %s (%d) <- %s\n           %s\n", e.When.Local().Format("15:04:05"), e.Name, e.PID, by, cut(command, 200))
		for _, a := range detect.Check(e) {
			alerted++
			fmt.Printf("    !! [%s] %s (%s; ATT&CK %s)\n", a.Severity, a.Title, a.ID, strings.Join(a.Attack, ", "))
		}
	})
	fmt.Printf("\n%d programs started, %d detections set off.\n", started, alerted)
	return err
}

// detectionList prints every detection: what it looks for and why.
func detectionList(markdown bool) {
	if markdown {
		fmt.Println("| Detection | Usually | What it catches | Why it matters | MITRE ATT&CK |")
		fmt.Println("| --- | --- | --- | --- | --- |")
		for _, d := range detect.All {
			var techniques []string
			for _, id := range d.Attack {
				techniques = append(techniques, id+" "+detect.Techniques[id])
			}
			fmt.Printf("| `%s` | %s | %s | %s | %s |\n", d.ID, d.Severity, d.Title, d.Why, strings.Join(techniques, "; "))
		}
		return
	}
	fmt.Printf("The live watch has %d detections.\n", len(detect.All))
	for _, d := range detect.All {
		fmt.Printf("\n%s  (usually: %s)\n    %s\n    %s\n    ATT&CK: %s\n", d.ID, strings.ToLower(d.Severity.String()), d.Title, d.Why, strings.Join(d.Attack, ", "))
	}
}
