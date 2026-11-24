package virustotal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The tests talk to a stand-in for VirusTotal on this PC. Nothing here
// reaches the internet.

const (
	testKey   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testPrint = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
	otherHash = "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"
)

// report is a made-up answer, shaped like the file reports VirusTotal's
// documentation describes. The engines are made up too.
func report(print string) string {
	return `{"data": {"id": "` + print + `", "type": "file", "links": {"self": "https://www.virustotal.com/api/v3/files/` + print + `"}, "attributes": {
		"sha256": "` + print + `", "last_analysis_date": 1763900000,
		"last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 60, "harmless": 0, "type-unsupported": 8, "timeout": 0, "confirmed-timeout": 0, "failure": 0},
		"last_analysis_results": {
			"Northwind AV": {"category": "malicious", "engine_name": "Northwind AV", "result": "Trojan.Example.A", "method": "blacklist"},
			"Contoso": {"category": "suspicious", "engine_name": "Contoso", "result": "Suspicious.Gen\r\nsecond line"},
			"Litware": {"category": "malicious", "engine_name": "Litware", "result": null},
			"Tailspin": {"category": "undetected", "engine_name": "Tailspin", "result": null},
			"Fabrikam": {"category": "malicious", "engine_name": "Fabrikam", "result": "Win32/Example"}
		},
		"meaningful_name": "example.exe", "reputation": -12, "type_description": "Win32 EXE",
		"popular_threat_classification": {"suggested_threat_label": "trojan.example/test"}
	}}}`
}

// stand starts a stand-in for VirusTotal and a client that talks to it,
// with a clock that moves only when the client waits.
func stand(t *testing.T, handler http.HandlerFunc) (*Client, *[]time.Duration) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	c.base = server.URL + "/api/v3/files/"
	clock := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	waits := &[]time.Duration{}
	c.now = func() time.Time { return clock }
	c.sleep = func(ctx context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		clock = clock.Add(d)
		return ctx.Err()
	}
	return c, waits
}

func refuse(status int, code string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(`{"error": {"code": "` + code + `", "message": "made-up words"}}`))
	}
}

// A file report is asked for the right way and read in full.
func TestLookReadsReport(t *testing.T) {
	c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v3/files/"+testPrint {
			t.Errorf("asked %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("x-apikey") != testKey {
			t.Error("the key was not sent in the x-apikey heading")
		}
		if r.URL.RawQuery != "" || strings.Contains(r.URL.String(), testKey) {
			t.Error("the key or something else was put into the address")
		}
		w.Write([]byte(report(testPrint)))
	})
	r, err := c.Look(context.Background(), strings.ToUpper(testPrint))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Known || r.Malicious != 3 || r.Suspicious != 1 || r.Undetected != 60 || r.Harmless != 0 || r.Engines() != 64 || r.Flags() != 4 {
		t.Errorf("read %+v", r)
	}
	if r.Label != "trojan.example/test" || r.Votes != -12 || r.Kind != "Win32 EXE" || r.KnownAs != "example.exe" {
		t.Errorf("read %+v", r)
	}
	if r.Analysed.Unix() != 1763900000 || r.Asked.IsZero() {
		t.Errorf("times: analysed %v, asked %v", r.Analysed, r.Asked)
	}
	var names []string
	for _, n := range r.Names {
		names = append(names, n.Engine+": "+n.Name)
	}
	// Sorted by engine, on one line each, and an engine with no name for it is left out.
	if got := strings.Join(names, " | "); got != "Contoso: Suspicious.Gen second line | Fabrikam: Win32/Example | Northwind AV: Trojan.Example.A" {
		t.Errorf("names: %s", got)
	}
	if Says(r) != "4 of 64" {
		t.Errorf("Says gave %q", Says(r))
	}
}

// A file VirusTotal has never seen is an answer, not an error.
func TestLookUnknownFile(t *testing.T) {
	c, _ := stand(t, refuse(http.StatusNotFound, "NotFoundError"))
	r, err := c.Look(context.Background(), testPrint)
	if err != nil || r.Known || r.Asked.IsZero() {
		t.Fatalf("got %+v, %v", r, err)
	}
	if Says(r) != "Not known" {
		t.Errorf("Says gave %q", Says(r))
	}
}

// Each refusal is told apart, and the ones that end a run say so.
func TestRefusals(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   error
		fatal  bool
	}{
		{401, "WrongCredentialsError", ErrKey, true},
		{401, "AuthenticationRequiredError", ErrKey, true},
		{401, "UserNotActiveError", ErrInactive, true},
		{429, "QuotaExceededError", ErrQuota, true},
		{429, "TooManyRequestsError", ErrBusy, false},
		{503, "TransientError", ErrBusy, false},
		{403, "ForbiddenError", nil, false},
	}
	for _, c := range cases {
		calls := 0
		client, waits := stand(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			refuse(c.status, c.code)(w, r)
		})
		_, err := client.Look(context.Background(), testPrint)
		var refusal *Error
		if !errors.As(err, &refusal) || refusal.Code != c.code || refusal.Status != c.status {
			t.Errorf("%s: got %v", c.code, err)
			continue
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v is not %v", c.code, err, c.want)
		}
		if Fatal(err) != c.fatal {
			t.Errorf("%s: Fatal gave %v", c.code, Fatal(err))
		}
		// The allowance of a minute is waited out once, and then asked again.
		wantCalls := 1
		if errors.Is(err, ErrQuota) || errors.Is(err, ErrBusy) {
			wantCalls = 2
			if len(*waits) == 0 || (*waits)[len(*waits)-1] != time.Minute {
				t.Errorf("%s: waited %v before asking again, want a minute", c.code, *waits)
			}
		}
		if calls != wantCalls {
			t.Errorf("%s: asked %d times, want %d", c.code, calls, wantCalls)
		}
	}
}

// A refusal for the minute's allowance that is gone a minute later costs
// nothing but the wait.
func TestQuotaWaitedOut(t *testing.T) {
	calls := 0
	c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			refuse(429, "QuotaExceededError")(w, r)
			return
		}
		w.Write([]byte(report(testPrint)))
	})
	if r, err := c.Look(context.Background(), testPrint); err != nil || !r.Known {
		t.Fatalf("got %+v, %v", r, err)
	}
}

// Lookups keep to the pace a free key allows: the first goes at once, and
// each after it waits its turn.
func TestPace(t *testing.T) {
	c, waits := stand(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(report(testPrint))) })
	for range 3 {
		if _, err := c.Look(context.Background(), testPrint); err != nil {
			t.Fatal(err)
		}
	}
	if len(*waits) != 2 || (*waits)[0] != Pace || (*waits)[1] != Pace {
		t.Errorf("waited %v, want two waits of %v", *waits, Pace)
	}
	if 60*time.Second/Pace >= PerMinute+1 || Pace*PerMinute < time.Minute {
		t.Errorf("a pace of %v breaks %d a minute", Pace, PerMinute)
	}
}

// A stopped run stops while waiting its turn, and asks nothing more.
func TestStopWhileWaiting(t *testing.T) {
	calls := 0
	c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(report(testPrint))) })
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := c.Look(ctx, testPrint); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := c.Look(ctx, testPrint); !errors.Is(err, context.Canceled) || !Fatal(err) {
		t.Errorf("a stopped run gave %v", err)
	}
	if calls != 1 {
		t.Errorf("asked %d times", calls)
	}
}

// A redirect is not followed, so the key never goes anywhere else.
func TestRedirectNotFollowed(t *testing.T) {
	reached := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer elsewhere.Close()
	c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusFound)
	})
	_, err := c.Look(context.Background(), testPrint)
	if !errors.Is(err, errRedirect) || !Fatal(err) {
		t.Errorf("a redirect gave %v", err)
	}
	if reached {
		t.Error("the redirect was followed, and the key went with it")
	}
}

// An answer about another file, or one that is too large or not data, is refused.
func TestBadAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"about another file": report(otherHash),
		"not data":           "<html>busy</html>",
		"too large":          `{"data": "` + strings.Repeat("x", most) + `"}`,
	} {
		c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
		if r, err := c.Look(context.Background(), testPrint); err == nil || Fatal(err) {
			t.Errorf("%s: got %+v, %v", name, r, err)
		}
	}
}

// A no-show from the network ends the run with a plain reason.
func TestOffline(t *testing.T) {
	c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) {})
	c.base = "http://127.0.0.1:1/api/v3/files/" // nothing answers there
	_, err := c.Look(context.Background(), testPrint)
	if !errors.Is(err, errOffline) || !Fatal(err) {
		t.Errorf("got %v", err)
	}
}

// Only a fingerprint can be looked up, and only a key-shaped key is used.
func TestInputs(t *testing.T) {
	c, _ := stand(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("asked about something that is not a fingerprint")
	})
	for _, bad := range []string{"", "notahash", testPrint[:63], testPrint + "0", "../" + testPrint[3:], testPrint[:60] + "zzzz"} {
		if _, err := c.Look(context.Background(), bad); err == nil {
			t.Errorf("%q was looked up", bad)
		}
	}
	for key, want := range map[string]bool{
		testKey: true, "  " + testKey + "\r\n": true, strings.ToUpper(testKey): true,
		testKey[:31]: false, testKey[:40] + "\r\nX-Other: 1": false, testKey + `"`: false, strings.Repeat("a", 129): false, "": false,
	} {
		if _, ok := CleanKey(key); ok != want {
			t.Errorf("CleanKey(%q) = %v", key, ok)
		}
	}
	if _, err := New("short"); !errors.Is(err, ErrForm) {
		t.Errorf("a short key gave %v", err)
	}
	if c, err := New(testKey); err != nil || c.Ends() != "cdef" {
		t.Errorf("Ends gave %q, %v", c.Ends(), err)
	}
}

func TestPage(t *testing.T) {
	if got := Page(testPrint); got != "https://www.virustotal.com/gui/file/"+testPrint {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{strings.ToUpper(testPrint), testPrint + "?x=1", "", "../../x"} {
		if got := Page(bad); got != "" {
			t.Errorf("Page(%q) = %q", bad, got)
		}
	}
}

func TestTidy(t *testing.T) {
	if got := tidy("a\r\nb\tc d\x00e", 50); got != "a b c d e" {
		t.Errorf("got %q", got)
	}
	if got := tidy(strings.Repeat("é", 10), 5); got != "éééé~" {
		t.Errorf("got %q", got)
	}
}

func TestRecent(t *testing.T) {
	now := time.Now()
	for asked, want := range map[time.Time]bool{now.Add(-time.Hour): true, now.Add(-8 * 24 * time.Hour): false, {}: false, now.Add(48 * time.Hour): false} {
		if got := Recent(answerAt(asked), now); got != want {
			t.Errorf("asked %v: %v", asked, got)
		}
	}
}
