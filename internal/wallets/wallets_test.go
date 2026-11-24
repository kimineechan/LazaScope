package wallets

import (
	"strings"
	"testing"

	"lazascope/internal/model"
)

func TestJudge(t *testing.T) {
	cases := []struct {
		browser, id, name string
		want              Claim
	}{
		{"Google Chrome", "nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask", Claim{Brand: "MetaMask", Verified: true}},
		{"Microsoft Edge", "ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask", Claim{Brand: "MetaMask", Verified: true}},
		{"Microsoft Edge", "nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask", Claim{Brand: "MetaMask", Verified: true}}, // Edge takes Chrome's store too
		{"Brave", "ljfoeinjpaedjfecbmggjgodbgkmjkjk", "MetaMask Flask DEVELOPMENT BUILD", Claim{Brand: "MetaMask", Verified: true}},
		{"Firefox", "webextension@metamask.io", "MetaMask", Claim{Brand: "MetaMask", Verified: true}},
		{"Google Chrome", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom", Claim{Brand: "Phantom", Verified: true}},
		{"Google Chrome", "abcdefghijklmnopabcdefghijklmnop", "MetaMask", Claim{Brand: "MetaMask", Fake: true}},
		{"Google Chrome", "abcdefghijklmnopabcdefghijklmnop", "Metamask Wallet Pro - Secure", Claim{Brand: "MetaMask", Fake: true}},
		{"Firefox", "metamask@example.com", "MetaMask", Claim{Brand: "MetaMask", Fake: true}},
		{"Google Chrome", "abcdefghijklmnopabcdefghijklmnop", "Phantom Wallet", Claim{Brand: "Phantom", Fake: true}},
		{"Google Chrome", "abcdefghijklmnopabcdefghijklmnop", "PhantomBuster", Claim{}},       // a different word
		{"Google Chrome", "abcdefghijklmnopabcdefghijklmnop", "Phantom Shield VPN", Claim{}},  // the word alone, not a wallet's name
		{"Google Chrome", "abcdefghijklmnopabcdefghijklmnop", "Keplr", Claim{Brand: "Keplr"}}, // no Chrome number known: not judged
		{"Firefox", "keplr@example.com", "Keplr", Claim{Brand: "Keplr", Fake: true}},          // the Firefox number is known
		{"Opera", "abcdefghijklmnopabcdefghijklmnop", "MetaMask", Claim{Brand: "MetaMask"}},   // Opera's store is not known
		{"Google Chrome", "cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin", Claim{}},
	}
	for _, c := range cases {
		if got := Judge(model.Extension{Browser: c.browser, ID: c.id, Name: c.name}); got != c.want {
			t.Errorf("%s %q (%s): got %+v, want %+v", c.browser, c.name, c.id, got, c.want)
		}
	}
	// Every number in the catalogue is written as its store writes it.
	for _, b := range brands {
		for _, id := range b.chromium {
			if len(id) != 32 || strings.Trim(id, "abcdefghijklmnop") != "" {
				t.Errorf("%s: %q is not a Chrome Web Store number", b.name, id)
			}
		}
	}
}

func TestLookAlike(t *testing.T) {
	for host, want := range map[string]string{
		"metamask-login.com": "MetaMask", "www.metamask-support.net": "MetaMask", "metamsk.io": "MetaMask", "mettamask.io": "MetaMask", "metmask.com": "MetaMask",
		"coinbase-verify.co.uk": "Coinbase", "c0inbase.com": "Coinbase", "binance-airdrop.xyz": "Binance", "uniswap-claim.app": "Uniswap", "etherscan-tx.org": "Etherscan",
		"phantomwallet-app.com": "Phantom", "trustwallet-recovery.com": "Trust Wallet",
		// Their own sites, and ordinary ones, are not look-alikes.
		"metamask.io": "", "api.metamask.io": "", "portfolio.metamask.io": "", "www.coinbase.com": "", "accounts.binance.com": "", "app.uniswap.org": "",
		"finance.yahoo.com": "", "phantomjs.org": "", "trevor.com": "", "news.bbc.co.uk": "", "github.io": "", "localhost": "",
	} {
		got, ok := LookAlike(host)
		if ok != (want != "") || got != want {
			t.Errorf("%s: got %q, %v; want %q", host, got, ok, want)
		}
	}
}

func TestRedirected(t *testing.T) {
	for _, c := range []struct {
		entry model.HostsEntry
		want  string
	}{
		{model.HostsEntry{Address: "203.0.113.9", Names: []string{"metamask.io"}}, "metamask.io"},
		{model.HostsEntry{Address: "203.0.113.9", Names: []string{"example.com", "www.coinbase.com"}}, "www.coinbase.com"},
		{model.HostsEntry{Address: "0.0.0.0", Names: []string{"metamask.io"}}, ""},   // blocked, not sent elsewhere
		{model.HostsEntry{Address: "127.0.0.1", Names: []string{"binance.com"}}, ""}, // blocked
		{model.HostsEntry{Address: "::1", Names: []string{"binance.com"}}, ""},
		{model.HostsEntry{Address: "203.0.113.9", Names: []string{"bank.example.com"}}, ""},
		{model.HostsEntry{Address: "not an address", Names: []string{"metamask.io"}}, ""},
	} {
		_, host, ok := Redirected(c.entry)
		if ok != (c.want != "") || host != c.want {
			t.Errorf("%+v: got %q, %v", c.entry, host, ok)
		}
	}
}

func TestMinerAndPrograms(t *testing.T) {
	for _, c := range []struct {
		p    model.Process
		want bool
	}{
		{model.Process{Name: "xmrig.exe", File: model.File{Path: `C:\Users\sam\AppData\Roaming\xmrig.exe`}}, true},
		{model.Process{Name: "svc.exe", File: model.File{Path: `C:\ProgramData\svc.exe`}, Command: `svc.exe -o stratum+ssl://pool.example.com:443`}, true},
		{model.Process{Name: "svc.exe", File: model.File{Path: `C:\ProgramData\svc.exe`}, Command: `svc.exe --donate-level 1 -o pool:3333`}, true},
		{model.Process{Name: "chrome.exe", File: model.File{Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`}, Command: `chrome.exe --type=renderer`}, false},
	} {
		if _, got := Miner(c.p); got != c.want {
			t.Errorf("%s %q: %v", c.p.Name, c.p.Command, got)
		}
	}
	for path, want := range map[string]string{`C:\Program Files\Electrum\electrum-4.5.8.exe`: "Electrum", `C:\Users\sam\AppData\Local\exodus\app-25.1.0\Exodus.exe`: "Exodus",
		`C:\Program Files\Ledger Live\Ledger Live.exe`: "Ledger Live", `C:\Windows\explorer.exe`: ""} {
		if got, ok := Program(path); got != want || ok != (want != "") {
			t.Errorf("%s: got %q", path, got)
		}
	}
}

func TestInventory(t *testing.T) {
	s := &model.Snapshot{
		Startup: []model.Startup{
			{Kind: model.BrowserExtension, Name: "MetaMask", Enabled: true, Extension: &model.Extension{Browser: "Google Chrome", Profile: "Default", ID: "nkbihfbeogaeaoehlefnkodbefgpgknn", Name: "MetaMask"}},
			{Kind: model.BrowserExtension, Name: "uBlock Origin", Enabled: true, Extension: &model.Extension{Browser: "Firefox", Profile: "default", ID: "uBlock0@raymondhill.net", Name: "uBlock Origin"}},
			{Kind: model.BrowserExtension, Name: "Some Crypto Wallet", Enabled: true, Extension: &model.Extension{Browser: "Google Chrome", Profile: "Default", ID: "bcdefghijklmnopabcdefghijklmnopa", Name: "Some Crypto Wallet"}},
		},
		Processes: []model.Process{{PID: 4410, Name: "Exodus.exe", File: model.File{Path: `C:\Users\sam\AppData\Local\exodus\app-25.1.0\Exodus.exe`}}},
		Clouds:    []model.CloudFolder{{Service: "OneDrive", Path: `C:\Users\sam\OneDrive`}},
	}
	found := []model.Wallet{{Name: "Monero", Kind: "Wallet files", Where: `C:\Users\sam\OneDrive\Documents\Monero\wallets`, Keys: true}}
	var got []string
	for _, w := range Inventory(s, found) {
		got = append(got, w.Name+"|"+w.Kind+"|"+w.Ref+"|"+w.Synced+"|"+map[bool]string{true: "real", false: "-"}[w.Verified])
	}
	want := "MetaMask|Browser extension|startup:0||real; Some Crypto Wallet|Browser extension|startup:2||-; Exodus|Program|process:4410||-; Monero|Wallet files||OneDrive|-"
	if strings.Join(got, "; ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, "; "), want)
	}
}
