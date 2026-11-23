//go:build windows

package main

import (
	"fmt"
	"time"

	"lazascope/internal/rules"
	"lazascope/internal/scan"
)

// healthList prints what Windows' own log says about the PC's hardware and
// about Windows stopping, and how full the disks are.
func healthList() error {
	s := scan.Run(scan.Parts{Health: true}, progress)
	c := s.Condition
	fmt.Printf("%s, %s, the last %d days\n\n", s.Computer, s.Windows, c.Days)
	stamp := func(when time.Time) string { return when.Local().Format("2006-01-02 15:04") }
	if !c.Read {
		fmt.Println("Windows' log of hardware errors and crashes could not be read.")
	} else {
		fmt.Printf("Hardware errors: %d\n", len(c.Hardware))
		for _, fault := range c.Hardware {
			fmt.Printf("  %s  %s\n", stamp(fault.When), fault.Words)
		}
		fmt.Printf("Blue-screen crashes: %d\n", len(c.Crashes))
		for _, crash := range c.Crashes {
			fmt.Printf("  %s  stop code 0x%X %s\n", stamp(crash.When), crash.Code, crash.Name)
		}
		fmt.Printf("Stops without a shutdown and without a blue screen: %d\n", len(c.PowerCuts))
		for _, when := range c.PowerCuts {
			fmt.Printf("  %s\n", stamp(when))
		}
		fmt.Printf("Disk faults: %d (and %d times a disk had to be asked twice)\n", len(c.Disk), c.Retries)
		for _, fault := range c.Disk {
			fmt.Printf("  %s  %s\n", stamp(fault.When), fault.Words)
		}
		fmt.Printf("Windows logs cleared: %d\n", len(c.Wiped))
		for _, wipe := range c.Wiped {
			fmt.Printf("  %s  %s, by %s\n", stamp(wipe.When), wipe.Log, wipe.By)
		}
	}
	for _, drive := range c.Drives {
		fmt.Printf("Drive %s  %s free of %s\n", drive.Letter, rules.Size(drive.Free), rules.Size(drive.Size))
	}
	if !c.Started.IsZero() {
		fmt.Printf("Windows running since %s\n", stamp(c.Started))
	}
	fmt.Println()
	for _, gap := range s.Gaps {
		fmt.Println("Could not see:", gap.What)
	}
	fmt.Printf("\nRead in %d ms\n", s.Took.Milliseconds())
	return nil
}
