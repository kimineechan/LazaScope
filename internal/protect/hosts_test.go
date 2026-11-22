package protect

import (
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	text := string(rune(0xFEFF)) + "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
		"#\r\n" +
		"#      102.54.94.97     rhino.acme.com          # source server\r\n" +
		"\r\n" +
		"127.0.0.1       localhost\r\n" +
		"::1             localhost\r\n" +
		"  0.0.0.0   ads.example.com   tracker.example.com  # blocked\r\n" +
		"203.0.113.9\tbank.example.com\r\n" +
		"justoneword\r\n" +
		"   \r\n"
	entries := ParseHosts(text)
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Address+"="+strings.Join(entry.Names, ","))
	}
	want := "127.0.0.1=localhost | ::1=localhost | 0.0.0.0=ads.example.com,tracker.example.com | 203.0.113.9=bank.example.com"
	if strings.Join(got, " | ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, " | "), want)
	}
	if len(ParseHosts("")) != 0 || len(ParseHosts("# only remarks\n# here")) != 0 {
		t.Error("a file with no working lines holds no entries")
	}
}
