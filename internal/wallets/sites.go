package wallets

import (
	"net/netip"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/winpath"
)

// service is a cryptocurrency service whose sites thieves copy, with the
// domains that are its own.
type service struct {
	name     string
	label    string   // the word in its domain, such as metamask
	official []string // its own domains; their subdomains are its own too
	typos    bool     // also catch names one letter away, for a word that is no ordinary word
}

var sites = []service{
	{"MetaMask", "metamask", []string{"metamask.io", "metamask.com"}, true},
	{"Coinbase", "coinbase", []string{"coinbase.com", "cb-w.com", "coinbase.us"}, true},
	{"Binance", "binance", []string{"binance.com", "binance.us", "binance.org", "binance.info", "binance.cloud", "bnbchain.org"}, false},
	{"Etherscan", "etherscan", []string{"etherscan.io", "etherscan.com"}, true},
	{"Uniswap", "uniswap", []string{"uniswap.org"}, true},
	{"OpenSea", "opensea", []string{"opensea.io"}, false},
	{"Trezor", "trezor", []string{"trezor.io"}, false},
	{"Trust Wallet", "trustwallet", []string{"trustwallet.com"}, false},
	{"Phantom", "phantomwallet", []string{"phantom.app", "phantom.com"}, false},
	{"Exodus", "exoduswallet", []string{"exodus.com", "exodus.io"}, false},
	{"Ledger", "ledgerlive", []string{"ledger.com"}, false},
	{"Blockchain.com", "blockchaincom", []string{"blockchain.com"}, false},
}

// The endings of names that take two parts, such as example.co.uk, so that
// the part a site picked is found. Only common ones are needed: a name that
// ends otherwise is read as name.ending.
var twoPart = map[string]bool{"co.uk": true, "org.uk": true, "com.au": true, "net.au": true, "co.jp": true, "com.br": true, "co.in": true, "com.cn": true,
	"co.nz": true, "co.za": true, "com.tr": true, "com.mx": true, "co.kr": true, "com.sg": true, "com.hk": true}

// registered returns the part of a host name that its owner registered,
// such as metamask.io for api.metamask.io, and the word they chose in it.
func registered(host string) (domain, word string) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host, host
	}
	keep := 2
	if len(parts) >= 3 && twoPart[parts[len(parts)-2]+"."+parts[len(parts)-1]] {
		keep = 3
	}
	if keep > len(parts) {
		keep = len(parts)
	}
	domain = strings.Join(parts[len(parts)-keep:], ".")
	return domain, parts[len(parts)-keep]
}

// Official returns the service a host name belongs to, when it is one of
// the service's own domains or below one.
func Official(host string) (string, bool) {
	domain, _ := registered(host)
	for _, s := range sites {
		for _, own := range s.official {
			if domain == own {
				return s.name, true
			}
		}
	}
	return "", false
}

// LookAlike reports whether a host name is dressed up as a cryptocurrency
// service's site without being one of its own: the service's word inside a
// domain it does not own, such as metamask-login.com, or for a word no
// dictionary has, a spelling one letter away, such as metamsk.io.
func LookAlike(host string) (string, bool) {
	if _, own := Official(host); own {
		return "", false
	}
	domain, word := registered(host)
	if domain == "" || word == "" {
		return "", false
	}
	plain := strings.NewReplacer("-", "", "_", "").Replace(word)
	for _, s := range sites {
		if strings.Contains(plain, s.label) {
			return s.name, true
		}
		if s.typos && len(plain) >= 6 && oneAway(plain, s.label) {
			return s.name, true
		}
	}
	return "", false
}

// oneAway reports whether two words differ by one letter added, dropped,
// changed or two letters swapped.
func oneAway(a, b string) bool {
	if a == b {
		return false
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == len(rb) {
		diff := []int{}
		for i := range ra {
			if ra[i] != rb[i] {
				diff = append(diff, i)
			}
		}
		if len(diff) == 1 {
			return true
		}
		return len(diff) == 2 && diff[1] == diff[0]+1 && ra[diff[0]] == rb[diff[1]] && ra[diff[1]] == rb[diff[0]]
	}
	if len(ra) < len(rb) {
		ra, rb = rb, ra
	}
	if len(ra)-len(rb) != 1 {
		return false
	}
	for i := range rb {
		if ra[i] != rb[i] {
			return string(ra[i+1:]) == string(rb[i:])
		}
	}
	return true
}

// Redirected reports whether a line of the hosts file sends a
// cryptocurrency service's own site to an address of someone else's
// choosing. A line that blocks the site, by sending it to this PC or to
// nowhere, is not this.
func Redirected(entry model.HostsEntry) (service, host string, ok bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(entry.Address))
	if err != nil || address.IsLoopback() || address.IsUnspecified() {
		return "", "", false
	}
	for _, name := range entry.Names {
		if s, own := Official(name); own {
			return s, name, true
		}
	}
	return "", "", false
}

// miners are the programs that mine cryptocurrency, by the name of their file.
var miners = map[string]bool{
	"xmrig.exe": true, "xmr-stak.exe": true, "xmr-stak-rx.exe": true, "nbminer.exe": true, "t-rex.exe": true, "lolminer.exe": true,
	"phoenixminer.exe": true, "ethminer.exe": true, "nanominer.exe": true, "teamredminer.exe": true, "srbminer-multi.exe": true,
	"gminer.exe": true, "bminer.exe": true, "ethdcrminer64.exe": true, "nicehashminer.exe": true, "nicehashquickminer.exe": true,
	"cpuminer.exe": true, "ccminer.exe": true, "excavator.exe": true, "trex.exe": true,
}

// Miner reports whether a running program is mining cryptocurrency, by its
// file's name or by the instructions on its command line, and says how.
func Miner(p model.Process) (string, bool) {
	if miners[strings.ToLower(winpath.Base(p.File.Path))] || miners[strings.ToLower(p.Name)] {
		return "its file has the name of a mining program", true
	}
	command := strings.ToLower(p.Command)
	for _, sign := range []string{"stratum+tcp://", "stratum+ssl://", "stratum+tls://", "stratum2+tcp://"} {
		if strings.Contains(command, sign) {
			return "it was told to join a mining pool (" + sign + ")", true
		}
	}
	if strings.Contains(command, "--donate-level") || strings.Contains(command, "--cpu-max-threads-hint") {
		return "its command line carries the settings of the miner XMRig", true
	}
	return "", false
}
