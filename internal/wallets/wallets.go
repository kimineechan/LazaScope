// Package wallets knows the cryptocurrency side of a PC: which wallets are
// on it, whether a wallet extension is the real one or a copy dressed up
// as it, where the wallet files are, and the names of the sites thieves
// copy. It never reads a wallet's contents, and never sends anything.
//
// Its catalogue is pure, so the rules that use it can be tested with
// made-up PCs. What it reads from the disk is in collect_windows.go.
package wallets

import (
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/winpath"
)

// brand is a wallet that comes as a browser extension, with the numbers
// its maker publishes for it. The numbers were read on 24 November 2026
// from the makers' own download pages (metamask.com, docs.metamask.com,
// phantom.com), from Microsoft's Edge Add-ons store, and from Mozilla's
// add-on catalogue, where each was published by the wallet's maker. A brand
// without numbers for a browser is not judged in that browser: a guess
// would call a real wallet a fake.
type brand struct {
	name     string
	chromium []string // Chrome Web Store and Edge Add-ons numbers
	firefox  []string // Firefox add-on numbers
	claims   func(name string) bool
}

var brands = []brand{
	{"MetaMask",
		[]string{"nkbihfbeogaeaoehlefnkodbefgpgknn", "ljfoeinjpaedjfecbmggjgodbgkmjkjk", "ejbalbakoplchlghecdalmeeeajnimhm"},
		[]string{"webextension@metamask.io", "webextension-flask@metamask.io", "legacyweb3@metamask.io"},
		func(n string) bool { return strings.Contains(n, "metamask") || strings.Contains(n, "meta mask") }},
	{"Phantom",
		[]string{"bfnaelmomeimhlpmgjnjophhpkkoljpa"},
		[]string{"{7c42eea1-b3e4-4be4-a56f-82a5852b12dc}"},
		// "Phantom" is a common word, so only a name that is the wallet's own
		// counts: Phantom, or Phantom with "wallet" in it.
		func(n string) bool { return n == "phantom" || (words(n)["phantom"] && strings.Contains(n, "wallet")) }},
	{"Ronin Wallet", nil, []string{"ronin-wallet@axieinfinity.com"}, func(n string) bool { return strings.Contains(n, "ronin wallet") }},
	{"Solflare", nil, []string{"{6d72262a-b243-4dc6-8f4f-be96c74e0a86}"}, func(n string) bool { return strings.Contains(n, "solflare") }},
	{"Keplr", nil, []string{"keplr-extension@keplr.app"}, func(n string) bool { return words(n)["keplr"] }},
	{"Yoroi", nil, []string{"{530f7c6c-6077-4703-8f71-cb368c663e35}"}, func(n string) bool { return words(n)["yoroi"] }},
	{"Enkrypt", nil, []string{"{21a9e8ea-7aa4-4aae-923c-ec8211f2779c}"}, func(n string) bool { return words(n)["enkrypt"] }},
	{"SubWallet", nil, []string{"{8a3a53f5-7490-46d7-b91d-f8549bb8df05}"}, func(n string) bool { return strings.Contains(n, "subwallet") }},
	{"Tonkeeper", nil, []string{"wallet@tonkeeper.com"}, func(n string) bool { return strings.Contains(n, "tonkeeper") }},
}

// words returns the words of a name, in small letters.
func words(name string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(name, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }) {
		out[w] = true
	}
	return out
}

// Claim is what can be said about an extension's claim to be a wallet.
type Claim struct {
	Brand    string // the wallet it is, or says it is; "" when it is no wallet the catalogue knows
	Verified bool   // its number is one the wallet's maker publishes
	Fake     bool   // it takes the wallet's name, and its number is none of the maker's
}

// family is the store an extension's number comes from.
func family(browser string) string {
	b := strings.ToLower(browser)
	switch {
	case strings.Contains(b, "firefox"):
		return "firefox"
	case strings.Contains(b, "opera"):
		// Opera has a store of its own, with numbers of its own, which the
		// catalogue does not hold: no Opera extension is judged.
		return ""
	}
	return "chromium" // Chrome, Edge, Brave and Vivaldi take Chrome Web Store numbers
}

func (b brand) ids(family string) []string {
	if family == "firefox" {
		return b.firefox
	}
	if family == "chromium" {
		return b.chromium
	}
	return nil
}

// Judge says whether an extension is a wallet, and whether it is the real
// one. An extension is called a fake only for a wallet whose real numbers
// for that browser are known.
func Judge(x model.Extension) Claim {
	f := family(x.Browser)
	id := strings.ToLower(strings.TrimSpace(x.ID))
	for _, b := range brands {
		for _, real := range b.ids(f) {
			if id == strings.ToLower(real) {
				return Claim{Brand: b.name, Verified: true}
			}
		}
	}
	name := strings.ToLower(x.Name)
	for _, b := range brands {
		if b.claims(name) {
			return Claim{Brand: b.name, Fake: len(b.ids(f)) > 0}
		}
	}
	return Claim{}
}

// walletName reports whether an extension calls itself a wallet, for the
// list of wallets: a name with "wallet" or "crypto" in it.
func walletName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "wallet") || words(n)["crypto"] || words(n)["web3"]
}

// folder is where a wallet program keeps its files, under one of the
// account's folders. The places are the programs' defaults, the same that
// published studies of password-stealing malware list as its targets.
type folder struct {
	wallet string
	under  string // appdata, localappdata or documents
	path   string
	keys   bool // the files can hold the keys to coins
}

var folders = []folder{
	{"Bitcoin Core", "appdata", `Bitcoin\wallets`, true},
	{"Bitcoin Core", "appdata", `Bitcoin\wallet.dat`, true},
	{"Electrum", "appdata", `Electrum\wallets`, true},
	{"Exodus", "appdata", `Exodus\exodus.wallet`, true},
	{"Atomic Wallet", "appdata", `atomic\Local Storage\leveldb`, true},
	{"Wasabi Wallet", "appdata", `WalletWasabi\Client\Wallets`, true},
	{"Sparrow", "appdata", `Sparrow\wallets`, true},
	{"Coinomi", "localappdata", `Coinomi\Coinomi\wallets`, true},
	{"Guarda", "appdata", `Guarda`, true},
	{"Litecoin Core", "appdata", `Litecoin\wallets`, true},
	{"Armory", "appdata", `Armory`, true},
	{"Jaxx Liberty", "appdata", `com.liberty.jaxx`, true},
	{"Monero", "documents", `Monero\wallets`, true},
	{"Ethereum keystore", "appdata", `Ethereum\keystore`, true},
	{"Ledger Live", "appdata", `Ledger Live`, false},
	{"Trezor Suite", "appdata", `@trezor\suite-desktop`, false},
}

// programs are the wallet programs known by the name of their file.
var programs = map[string]string{
	"exodus.exe": "Exodus", "electrum.exe": "Electrum", "bitcoin-qt.exe": "Bitcoin Core", "litecoin-qt.exe": "Litecoin Core",
	"atomic wallet.exe": "Atomic Wallet", "wasabi wallet.exe": "Wasabi Wallet", "wassabee.exe": "Wasabi Wallet", "sparrow.exe": "Sparrow",
	"coinomi.exe": "Coinomi", "guarda.exe": "Guarda", "monero-wallet-gui.exe": "Monero", "ledger live.exe": "Ledger Live", "trezor suite.exe": "Trezor Suite",
}

// Program returns the wallet a program file belongs to, if it is a wallet
// program the catalogue knows. Electrum's file carries its version in its
// name, such as electrum-4.5.8.exe.
func Program(path string) (string, bool) {
	base := strings.ToLower(winpath.Base(path))
	if name, ok := programs[base]; ok {
		return name, true
	}
	if strings.HasPrefix(base, "electrum-") && strings.HasSuffix(base, ".exe") {
		return "Electrum", true
	}
	return "", false
}

// Inventory lists the wallets in a look: the extensions that are wallets or
// say they are, the wallet programs that run or start, and the folders of
// wallet files found. found holds those folders, by wallet, as Collect
// reads them from the disk.
func Inventory(s *model.Snapshot, found []model.Wallet) []model.Wallet {
	var out []model.Wallet
	for i, e := range s.Startup {
		x := e.Extension
		if x == nil {
			continue
		}
		c := Judge(*x)
		if c.Brand == "" && !walletName(x.Name) {
			continue
		}
		name := x.Name
		if c.Verified {
			name = c.Brand
		}
		out = append(out, model.Wallet{Name: name, Kind: "Browser extension", Where: x.Browser + ", profile " + x.Profile,
			Verified: c.Verified, Keys: true, Ref: "startup:" + strconv.Itoa(i)})
	}
	seen := map[string]bool{}
	for _, p := range s.Processes {
		name, ok := Program(p.File.Path)
		if !ok || seen[strings.ToLower(p.File.Path)] {
			continue
		}
		seen[strings.ToLower(p.File.Path)] = true
		out = append(out, model.Wallet{Name: name, Kind: "Program", Where: p.File.Path, Keys: name != "Ledger Live" && name != "Trezor Suite", Ref: "process:" + strconv.Itoa(int(p.PID))})
	}
	for _, e := range s.Startup {
		name, ok := Program(e.Works().Path)
		if !ok || seen[strings.ToLower(e.Works().Path)] || !e.Enabled {
			continue
		}
		seen[strings.ToLower(e.Works().Path)] = true
		out = append(out, model.Wallet{Name: name, Kind: "Program", Where: e.Works().Path, Keys: name != "Ledger Live" && name != "Trezor Suite"})
	}
	for _, w := range found {
		w.Synced = Synced(w.Where, s.Clouds)
		out = append(out, w)
	}
	return out
}

// Synced returns the cloud service that copies a path off the PC, if any.
func Synced(path string, clouds []model.CloudFolder) string {
	for _, c := range clouds {
		if c.Path != "" && (winpath.Under(path, c.Path) || winpath.Same(path, c.Path)) {
			return c.Service
		}
	}
	return ""
}
