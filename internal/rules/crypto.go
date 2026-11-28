package rules

import (
	"lazascope/internal/i18n"
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
	"lazascope/internal/wallets"
)

// Crypto returns the names of the cryptocurrency rules.
func Crypto() map[string]bool {
	names := map[string]bool{}
	for _, rule := range cryptoRules {
		names[rule.ID] = true
	}
	return names
}

// listed joins words the way a sentence does: a, b and c.
func listed(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// The cryptocurrency rules: fake wallets, wallet files left where they can
// be copied, the clipboard, mining, and the sites thieves copy. None of
// them opens a wallet or reads a key; they look at where things are and
// what they are called.

var cryptoRules = []Rule{
	{
		ID: "extension-fake-wallet", Area: model.StartsWithWindows, Severity: High,
		Title: i18n.T("An extension takes a wallet's name, but is not that wallet"),
		Why:   i18n.T("Fake wallet extensions copy a real wallet's name and look, then send the recovery phrase typed into them to a thief. An extension's number tells them apart: the makers of a wallet publish the number of the real one."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, e := range s.Startup {
				x := e.Extension
				if x == nil {
					continue
				}
				claim := wallets.Judge(*x)
				if !claim.Fake {
					continue
				}
				r.at(StartupRef(i))
				reason := x.Name + " in " + x.Browser + " (profile " + x.Profile + ") calls itself " + claim.Brand + ", but its number, " + x.ID +
					", is not one that " + claim.Brand + "'s makers publish. A copy of a wallet is built to steal the recovery phrase typed into it."
				if !x.Enabled {
					reason += " It is switched off at the moment."
				}
				found = append(found, r.find(x.Name, reason,
					i18n.T("Do not type a recovery phrase or a password into it. Remove it from the browser: open the browser's menu, choose Extensions, then Remove. If you ever typed a recovery phrase into it, treat that phrase as known to a thief: from a device you trust, make a new wallet with a new phrase and move the coins to it at once."),
					about(e)...))
			}
			return
		},
	},
	{
		ID: "wallet-program-unsigned", Area: model.RunningNow, Severity: Medium,
		Title: i18n.T("A wallet program carries no working signature from its maker"),
		Why:   i18n.T("Fake copies of wallet programs are a common way to steal coins. Most makers sign their wallet programs, so a missing or broken signature is a reason to check where this one came from."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, p := range once(s.Processes) {
				name, ok := wallets.Program(p.File.Path)
				if !ok || !p.File.Exists || p.File.Signature.Status == sigcheck.Signed || p.File.Signature.Status == sigcheck.Unknown {
					continue
				}
				r.at(FileRef(p.File.Path))
				reason := p.Name + " is the program of the " + name + " wallet, and its file carries no maker's signature."
				f := r.find(p.Name, reason, "", aboutProcess(s, p)...)
				if p.File.Signature.Status == sigcheck.Invalid {
					f.Severity = High
					f.Reason = p.Name + " is the program of the " + name + " wallet, and its file carries a signature that does not hold: " + Signature(p.File) + "."
				}
				f.Advice = i18n.T("Check that it came from ") + name + "'s own website. Wallet makers publish a fingerprint (SHA-256) for each download: on the Wallets page, paste it and choose Check a download... to compare. If it does not match, uninstall the program and, from a device you trust, move the coins to a new wallet with a new recovery phrase."
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "wallet-files-synced", Area: model.Protection, Severity: Medium, Topic: "wallets",
		Title: i18n.T("Wallet files are copied to a cloud service"),
		Why:   i18n.T("Wallet files can hold the keys to coins. In a folder that a cloud service copies, they are also wherever that account is: anyone who gets into the account gets a copy."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, w := range s.Wallets {
				if w.Synced == "" || !w.Keys || w.Kind != "Wallet files" {
					continue
				}
				found = append(found, r.find(w.Name,
					w.Name+"'s files, which can hold the keys to coins, are in "+w.Where+", a folder that "+w.Synced+" copies to the internet. Most wallets lock their files with a password, which is then all that stands between whoever gets into the "+w.Synced+" account and the coins.",
					i18n.T("Move the wallet's files out of the synced folder, or at least make sure the wallet has a long password of its own and the ")+w.Synced+" account has two-step sign-in.",
					Fact{"Wallet", w.Name}, Fact{"Folder", w.Where}, Fact{"Copied by", w.Synced}))
			}
			return
		},
	},
	{
		ID: "wallet-files-unencrypted", Area: model.Protection, Severity: Low, Topic: "wallets",
		Title: i18n.T("Wallet files are on a disk that is not encrypted"),
		Why:   i18n.T("Without encryption, anyone who takes the PC or its disk can copy every file on it, wallet files included."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			open := map[string]bool{}
			for _, v := range s.Guard.Volumes {
				if v.Encrypted == model.No {
					open[strings.ToUpper(strings.TrimSuffix(v.Drive, `\`))] = true
				}
			}
			var names, drives []string
			for _, w := range s.Wallets {
				if w.Kind != "Wallet files" || !w.Keys || len(w.Where) < 2 || !open[strings.ToUpper(w.Where[:2])] {
					continue
				}
				names = append(names, w.Name)
				drives = append(drives, strings.ToUpper(w.Where[:2]))
			}
			if len(names) == 0 {
				return
			}
			found = append(found, r.find(strings.Join(names, ", "),
				"The files of "+listed(names)+" are on drive "+listed(each(drives))+", which is not encrypted. Anyone who takes the PC or its disk can copy them. Most wallets lock their files with a password too.",
				i18n.T("Switch on BitLocker, or Device encryption where Windows offers it (in Settings, under Privacy and security on Windows 11, or Update and Security on Windows 10), and give each wallet a long password of its own."),
				Fact{"Wallets", strings.Join(names, ", ")}))
			return
		},
	},
	{
		ID: "clipboard-history-wallets", Area: model.Protection, Severity: Low, Topic: "clipboard",
		Title: i18n.T("Windows keeps a history of what is copied, on a PC with a wallet"),
		Why:   i18n.T("With clipboard history on, whatever is copied stays in a list that anyone at the PC can open with Windows key + V. A copied recovery phrase or private key stays there too."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			if s.Clipboard.History != model.Yes {
				return
			}
			var names []string
			for _, w := range s.Wallets {
				if w.Keys {
					names = append(names, w.Name)
				}
			}
			if len(names) == 0 {
				return
			}
			names = each(names)
			reason := i18n.T("Clipboard history is on, and this PC has a wallet (") + listed(names) + "). Whatever is copied, a recovery phrase or a private key included, stays in the list that Windows key + V shows until the PC restarts or the list is cleared."
			f := r.find("Clipboard history", reason, i18n.T("Never copy a recovery phrase. To switch the history off, open Settings, then System, then Clipboard, and turn Clipboard history off. Clear clipboard data on the same page empties it now."),
				Fact{"Clipboard history", "On"}, Fact{"Wallets", strings.Join(names, ", ")})
			if s.Clipboard.Cloud == model.Yes {
				f.Severity = Medium
				f.Reason += " It is also sent to the other devices signed in to the same Microsoft account."
				f.Facts = append(f.Facts, Fact{i18n.T("Sent to other devices"), "Yes"})
			}
			found = append(found, f)
			return
		},
	},
	{
		ID: "hosts-crypto-redirect", Area: model.Protection, Severity: High, Topic: "hosts",
		Title: i18n.T("The hosts file sends a cryptocurrency site somewhere else"),
		Why:   i18n.T("A line in the hosts file decides where a website's name leads on this PC. Pointing a wallet's or an exchange's own name at another address lets a fake copy of the site show the real name in the address bar."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, entry := range s.Guard.Hosts {
				service, host, ok := wallets.Redirected(entry)
				if !ok {
					continue
				}
				found = append(found, r.find(host,
					"The hosts file tells this PC that "+host+", "+service+"'s own site, is at "+entry.Address+". Every program on the PC, the browser included, then goes there instead of to "+service+".",
					"Unless you added this line yourself for testing, remove it: open Notepad as administrator, open "+s.Guard.HostsPath+", delete the line and save. Then scan the PC with your antivirus, and do not sign in to "+service+" from this PC until that is done.",
					Fact{"Name", host}, Fact{"Sent to", entry.Address}, Fact{"File", s.Guard.HostsPath}))
			}
			return
		},
	},
	{
		ID: "crypto-lookalike-site", Area: model.Connections, Severity: Medium,
		Title: i18n.T("A program talked to a site named like a cryptocurrency service"),
		Why:   i18n.T("Copies of wallet and exchange sites use names built from the real ones, such as metamask-login.com, to catch people who misread them. This is read from the names this PC looked up, which Windows remembers for a while."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			seen := map[string]bool{}
			for i, c := range s.Connections {
				for _, name := range c.Names {
					service, ok := wallets.LookAlike(name)
					if !ok || seen[strings.ToLower(name)] {
						continue
					}
					seen[strings.ToLower(name)] = true
					r.at(ConnectionRef(i))
					found = append(found, r.find(name,
						c.Process+" is connected to "+name+", a name built from "+service+"'s but not one of "+service+"'s own sites.",
						i18n.T("If you opened this site, close it, and do not type a recovery phrase, a password or a code into it. Go to ")+service+" by typing its address yourself. If no browser of yours was open on it, scan the PC with your antivirus.",
						Fact{"Name", name}, Fact{"Address", c.Remote}, Fact{"Program", c.Process + " (process " + strconv.Itoa(int(c.PID)) + ")"}, Fact{"File", c.File.Path}))
				}
			}
			return
		},
	},
	{
		ID: "running-miner", Area: model.RunningNow, Severity: Medium,
		Title: i18n.T("A program is mining cryptocurrency"),
		Why:   i18n.T("Mining keeps the processor or the graphics card busy for hours, which costs electricity and wears the PC. Some people mine on purpose; malware that mines for someone else is common too."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, p := range once(s.Processes) {
				how, ok := wallets.Miner(p)
				if !ok {
					continue
				}
				r.at(FileRef(p.File.Path))
				found = append(found, r.find(p.Name, p.Name+" is mining cryptocurrency: "+how+".",
					seeRunning+i18n.T("If you did not set mining up yourself, end it there, look for what starts it under 03 Start-up, and scan the PC with your antivirus."), aboutProcess(s, p)...))
			}
			return
		},
	},
	{
		ID: "clipboard-address-swapped", Area: model.RunningNow, Severity: High, Topic: "swaptest",
		Title: i18n.T("A program swapped a copied wallet address for another"),
		Why:   i18n.T("Clipboard-stealing malware watches for a copied wallet address and puts the thief's in its place, so that coins sent to the pasted address go to the thief. LazaScope's address-swap test copies made-up addresses that no wallet accepts, and watches."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			t := s.SwapTest
			if t == nil || !t.Swapped {
				return
			}
			if t.PID != 0 {
				r.at(ProcessRef(t.PID))
			}
			who := t.By
			if who == "" {
				who = i18n.T("A program Windows did not name")
			}
			reason := i18n.T("LazaScope copied a made-up ") + t.Kind + " address, and a moment later the clipboard held another: " + t.Into + "."
			if t.By != "" {
				reason += " Windows says the clipboard was last changed by " + t.By + " (process " + strconv.Itoa(int(t.PID)) + ")."
			}
			facts := []Fact{{"Address tried", t.Kind}, {"Swapped for", t.Into}, {"Program", t.By}, {"File", t.Path}}
			found = append(found, r.find(who, reason,
				i18n.T("Do not send coins from this PC until it is cleaned. Scan it with your antivirus, end the program in Task Manager, and look for it under 03 Start-up. Whenever you paste an address, check it character by character against the one you meant."),
				facts...))
			return
		},
	},
}
