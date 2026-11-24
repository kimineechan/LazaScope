// Package virustotal asks VirusTotal what the antivirus engines it runs
// make of a file. VirusTotal is a website, owned by Google, that runs each
// file it is shown through about 70 antivirus engines and keeps their
// verdicts. It is asked by the file's fingerprint (its SHA-256), so the
// file itself never leaves the PC, and only with a key that the person
// using LazaScope set up for themselves.
//
// This is the one part of LazaScope that reaches the internet. No other
// package may import Go's network packages; a test checks that.
//
// The free key (VirusTotal's Public API) allows 4 lookups a minute and 500
// a day, for personal use that is not commercial. These figures and the
// shape of the answers were checked on docs.virustotal.com on 24 November
// 2026.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"lazascope/internal/model"
)

const (
	PerMinute = 4   // lookups a free key may make in a minute
	PerDay    = 500 // and in a day, which starts again at midnight UTC

	// Pace is the time left between two lookups, which keeps a free key
	// within its 4 a minute with a little to spare.
	Pace = 15*time.Second + 500*time.Millisecond

	// Fresh is how long an answer is used before VirusTotal is asked again.
	// The engines' verdicts on a file change slowly, and lookups are few.
	Fresh = 7 * 24 * time.Hour

	host  = "https://www.virustotal.com"
	most  = 8 << 20 // the largest answer read, in bytes; a file report is usually far smaller
	names = 12      // how many engines' names for a flagged file are kept
)

// Page returns the address of VirusTotal's own page about a file, to open
// in a browser, or "" for anything that is not a SHA-256 fingerprint, so
// that nothing but a fingerprint can be put into the address.
func Page(print string) string {
	if !ValidHash(print) {
		return ""
	}
	return host + "/gui/file/" + print
}

// ValidHash reports whether text is a SHA-256 fingerprint: 64 digits and
// letters a to f, in small letters.
func ValidHash(text string) bool {
	if len(text) != 64 {
		return false
	}
	for _, r := range text {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// CleanKey tidies a pasted key and reports whether it can be a VirusTotal
// key: letters and digits only, between 32 and 128 of them. A key is sent
// in the heading of every request, so nothing else may get through.
func CleanKey(key string) (string, bool) {
	key = strings.TrimSpace(key)
	if len(key) < 32 || len(key) > 128 {
		return key, false
	}
	for _, r := range key {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return key, false
		}
	}
	return key, true
}

// The refusals that change what LazaScope does next.
var (
	ErrKey      = errors.New("VirusTotal did not accept the key. Check that it was copied whole, from the API key page of your VirusTotal account")
	ErrInactive = errors.New("the VirusTotal account is not active yet. Open the link VirusTotal sent by email, then try again")
	ErrQuota    = errors.New("the key has used up its lookups for now. A free key may make 4 lookups a minute and 500 a day, and the day starts again at midnight UTC")
	ErrBusy     = errors.New("VirusTotal is busy. Try again in a minute")
	ErrForm     = errors.New("that does not look like a VirusTotal key. A key is a long run of letters and digits, shown on the API key page of your VirusTotal account")
	errRedirect = errors.New("VirusTotal sent the request on to another address, which LazaScope does not follow, because the key would go with it")
)

// Error is a refusal from VirusTotal, with its own code and words.
type Error struct {
	Status  int    // the web status number, such as 401
	Code    string // VirusTotal's code, such as WrongCredentialsError
	Message string // VirusTotal's own words
}

// Is lets errors.Is tell the refusals that matter apart.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrInactive:
		return e.Code == "UserNotActiveError"
	case ErrKey:
		return e.Status == http.StatusUnauthorized && e.Code != "UserNotActiveError"
	case ErrQuota:
		// VirusTotal uses this code for the minute's allowance too.
		return e.Code == "QuotaExceededError"
	case ErrBusy:
		return e.Code == "TooManyRequestsError" || e.Code == "TransientError" || e.Code == "DeadlineExceededError" ||
			e.Status >= 500 || (e.Status == http.StatusTooManyRequests && e.Code != "QuotaExceededError")
	}
	return false
}

func (e *Error) Error() string {
	for _, known := range []error{ErrKey, ErrInactive, ErrQuota, ErrBusy} {
		if e.Is(known) {
			return known.Error()
		}
	}
	text := fmt.Sprintf("VirusTotal refused the lookup (%d", e.Status)
	if e.Code != "" {
		text += " " + e.Code
	}
	text += ")"
	if e.Message != "" {
		text += ": " + e.Message
	}
	return text
}

// Fatal reports whether an error means that no more lookups will work for
// now, so that a run of them should stop: the key is refused, the account
// is not active, the allowance is used up, or the run was stopped.
func Fatal(err error) bool {
	return errors.Is(err, ErrKey) || errors.Is(err, ErrInactive) || errors.Is(err, ErrQuota) ||
		errors.Is(err, context.Canceled) || errors.Is(err, errRedirect) || errors.Is(err, errOffline)
}

var errOffline = errors.New("VirusTotal could not be reached. Check that this PC is online")

// Client asks VirusTotal with one key, and keeps to the pace a free key
// allows. It is safe to use from several goroutines at once: they take
// turns.
type Client struct {
	key   string
	base  string // where file reports are asked for; only tests change it
	web   *http.Client
	pace  time.Duration
	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	mu   sync.Mutex
	next time.Time // the earliest the next lookup may go
}

// New prepares to ask VirusTotal with a key.
func New(key string) (*Client, error) {
	key, ok := CleanKey(key)
	if !ok {
		return nil, ErrForm
	}
	return &Client{key: key, base: host + "/api/v3/files/", pace: Pace, now: time.Now, sleep: pause,
		web: &http.Client{
			Timeout: 30 * time.Second,
			// A redirect would carry the key wherever it points, so none is followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
		}}, nil
}

// pause waits, or stops early when the context is cancelled.
func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Ends returns the last four characters of the key, to show which key is
// in use without showing the key.
func (c *Client) Ends() string { return c.key[len(c.key)-4:] }

// Wait returns how long the next lookup must wait for its turn.
func (c *Client) Wait() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max(c.next.Sub(c.now()), 0)
}

// turn waits until a lookup may go, and books the turn after it.
func (c *Client) turn(ctx context.Context) error {
	c.mu.Lock()
	now := c.now()
	at := c.next
	if at.Before(now) {
		at = now
	}
	c.next = at.Add(c.pace)
	c.mu.Unlock()
	if wait := at.Sub(now); wait > 0 {
		return c.sleep(ctx, wait)
	}
	return nil
}

// Look asks VirusTotal what it knows about a file, by the file's SHA-256
// fingerprint. It waits its turn first. A file VirusTotal has never seen
// gives a Reputation with Known false, and no error.
//
// VirusTotal counts lookups by the minute as well as by the day. One
// refusal of that kind is waited out, a minute long, and the lookup made
// again; a second refusal is returned.
func (c *Client) Look(ctx context.Context, print string) (model.Reputation, error) {
	print = strings.ToLower(print)
	if !ValidHash(print) {
		return model.Reputation{}, fmt.Errorf("%q is not a SHA-256 fingerprint", print)
	}
	for attempt := 0; ; attempt++ {
		if err := c.turn(ctx); err != nil {
			return model.Reputation{}, err
		}
		r, err := c.ask(ctx, print)
		if attempt == 0 && (errors.Is(err, ErrQuota) || errors.Is(err, ErrBusy)) {
			c.mu.Lock()
			c.next = c.now().Add(time.Minute)
			c.mu.Unlock()
			continue
		}
		return r, err
	}
}

// ask makes one lookup.
func (c *Client) ask(ctx context.Context, print string) (model.Reputation, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+print, nil)
	if err != nil {
		return model.Reputation{}, err
	}
	request.Header.Set("x-apikey", c.key)
	request.Header.Set("Accept", "application/json")
	response, err := c.web.Do(request)
	if err != nil {
		switch {
		case errors.Is(err, errRedirect):
			return model.Reputation{}, errRedirect
		case ctx.Err() != nil:
			return model.Reputation{}, ctx.Err()
		}
		return model.Reputation{}, fmt.Errorf("%w (%v)", errOffline, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, most+1))
	if err != nil {
		return model.Reputation{}, fmt.Errorf("VirusTotal's answer was cut off: %w", err)
	}
	if len(body) > most {
		return model.Reputation{}, errors.New("VirusTotal's answer was larger than LazaScope reads")
	}
	asked := c.now()
	switch response.StatusCode {
	case http.StatusOK:
		return Parse(body, print, asked)
	case http.StatusNotFound:
		// VirusTotal has never been shown this file. LazaScope never shows it
		// the file, so it stays that way.
		return model.Reputation{Asked: asked}, nil
	}
	var refusal struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	json.Unmarshal(body, &refusal) // a refusal that cannot be read still has its status
	return model.Reputation{}, &Error{Status: response.StatusCode, Code: tidy(refusal.Error.Code, 60), Message: tidy(refusal.Error.Message, 200)}
}

// Parse reads VirusTotal's report on a file. The report must be about the
// file that was asked about.
func Parse(body []byte, print string, asked time.Time) (model.Reputation, error) {
	var report struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				SHA256   string         `json:"sha256"`
				Analysed int64          `json:"last_analysis_date"`
				Stats    map[string]int `json:"last_analysis_stats"`
				Results  map[string]struct {
					Category string  `json:"category"`
					Engine   string  `json:"engine_name"`
					Result   *string `json:"result"`
				} `json:"last_analysis_results"`
				Name       string `json:"meaningful_name"`
				Reputation int    `json:"reputation"`
				Kind       string `json:"type_description"`
				Popular    struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		return model.Reputation{}, fmt.Errorf("VirusTotal's answer could not be read: %w", err)
	}
	a := report.Data.Attributes
	about := strings.ToLower(a.SHA256)
	if about == "" {
		about = strings.ToLower(report.Data.ID)
	}
	if report.Data.Type != "file" || about != strings.ToLower(print) {
		return model.Reputation{}, errors.New("VirusTotal answered about something other than the file it was asked about")
	}
	r := model.Reputation{Asked: asked, Known: true,
		Malicious: max(a.Stats["malicious"], 0), Suspicious: max(a.Stats["suspicious"], 0),
		Undetected: max(a.Stats["undetected"], 0), Harmless: max(a.Stats["harmless"], 0),
		Label: tidy(a.Popular.Label, 120), Votes: a.Reputation, Kind: tidy(a.Kind, 80), KnownAs: tidy(a.Name, 160)}
	if a.Analysed > 0 {
		r.Analysed = time.Unix(a.Analysed, 0)
	}
	for key, result := range a.Results {
		if result.Category != "malicious" && result.Category != "suspicious" || result.Result == nil {
			continue
		}
		engine := result.Engine
		if engine == "" {
			engine = key
		}
		if name := tidy(*result.Result, 120); name != "" {
			r.Names = append(r.Names, model.EngineName{Engine: tidy(engine, 60), Name: name})
		}
	}
	sort.Slice(r.Names, func(i, j int) bool { return strings.ToLower(r.Names[i].Engine) < strings.ToLower(r.Names[j].Engine) })
	if len(r.Names) > names {
		r.Names = r.Names[:names]
	}
	return r, nil
}

// tidy makes text from VirusTotal safe to show on one line: no control
// characters, and no longer than it should be.
func tidy(text string, most int) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, text)
	text = strings.Join(strings.Fields(text), " ")
	if runes := []rune(text); len(runes) > most {
		text = string(runes[:most-1]) + "~"
	}
	return text
}

// Says sums up an answer in a few words, for a column of a table: "3 of
// 71", "Not known" for a file VirusTotal has never seen.
func Says(r model.Reputation) string {
	switch {
	case !r.Known:
		return "Not known"
	case r.Engines() == 0:
		return "No verdicts"
	}
	return fmt.Sprintf("%d of %d", r.Flags(), r.Engines())
}

// Recent reports whether an answer is young enough to use without asking
// again.
func Recent(r model.Reputation, now time.Time) bool {
	return !r.Asked.IsZero() && now.Sub(r.Asked) < Fresh && now.Sub(r.Asked) > -time.Hour
}
