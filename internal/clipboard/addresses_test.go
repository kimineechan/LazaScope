//go:build windows

package clipboard

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	"regexp"
	"strings"
	"testing"
)

// The made-up addresses must look like addresses to a clipper and be
// refused by every wallet. These tests check both, with each kind's own
// checksum worked out here from its published definition.

// The patterns clippers are known to use, and wallets too, to spot an address.
var shapes = map[string]*regexp.Regexp{
	"Bitcoin":       regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`),
	"Bitcoin (bc1)": regexp.MustCompile(`^bc1[ac-hj-np-z02-9]{11,71}$`),
	"Ethereum":      regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`),
}

func TestAddressesLookRight(t *testing.T) {
	for _, a := range Addresses {
		if !shapes[a.Kind].MatchString(a.Text) {
			t.Errorf("%s: %q does not have the shape a clipper looks for", a.Kind, a.Text)
		}
	}
}

// Base58Check, Bitcoin's old kind of address: the last four bytes are the
// start of a double SHA-256 of the rest.
func TestBitcoinChecksumFails(t *testing.T) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	decode := func(s string) []byte {
		n := new(big.Int)
		for _, r := range s {
			n.Mul(n, big.NewInt(58))
			n.Add(n, big.NewInt(int64(strings.IndexRune(alphabet, r))))
		}
		out := n.Bytes()
		for _, r := range s {
			if r != '1' {
				break
			}
			out = append([]byte{0}, out...)
		}
		return out
	}
	valid := func(s string) bool {
		b := decode(s)
		if len(b) != 25 {
			return false
		}
		first := sha256.Sum256(b[:21])
		second := sha256.Sum256(first[:])
		return string(second[:4]) == string(b[21:])
	}
	// A real address from Bitcoin's own early history checks, so the checker works.
	if !valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") {
		t.Fatal("the Base58Check checker refuses a real address")
	}
	if valid(Addresses[0].Text) {
		t.Errorf("%q passes its checksum, so a wallet would accept it", Addresses[0].Text)
	}
}

// Bech32 (BIP 173), Bitcoin's newer kind: a checksum over the five-bit groups.
func TestBech32ChecksumFails(t *testing.T) {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	polymod := func(values []int) int {
		gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
		chk := 1
		for _, v := range values {
			top := chk >> 25
			chk = (chk&0x1ffffff)<<5 ^ v
			for i := range 5 {
				if (top>>i)&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	valid := func(s string) bool {
		s = strings.ToLower(s)
		sep := strings.LastIndex(s, "1")
		hrp, data := s[:sep], s[sep+1:]
		var values []int
		for _, r := range hrp {
			values = append(values, int(r)>>5)
		}
		values = append(values, 0)
		for _, r := range hrp {
			values = append(values, int(r)&31)
		}
		for _, r := range data {
			i := strings.IndexRune(charset, r)
			if i < 0 {
				return false
			}
			values = append(values, i)
		}
		return polymod(values) == 1 || polymod(values) == 0x2bc830a3 // bech32 or bech32m
	}
	// The example address from BIP 173 checks, so the checker works.
	if !valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") {
		t.Fatal("the bech32 checker refuses BIP 173's own example")
	}
	if valid(Addresses[1].Text) {
		t.Errorf("%q passes its checksum, so a wallet would accept it", Addresses[1].Text)
	}
}

// EIP-55: in an Ethereum address with capitals, each letter is a capital
// exactly when the matching part of the Keccak-256 of the small-letter
// address is 8 or more.
func TestEthereumChecksumFails(t *testing.T) {
	if got := hex.EncodeToString(keccak256(nil)); got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("Keccak-256 of nothing is %s; the hash below is wrong", got)
	}
	valid := func(address string) bool {
		plain := strings.ToLower(address[2:])
		hash := hex.EncodeToString(keccak256([]byte(plain)))
		for i, r := range address[2:] {
			if r >= '0' && r <= '9' {
				continue
			}
			capital := r >= 'A' && r <= 'F'
			if capital != (hash[i] >= '8') {
				return false
			}
		}
		return true
	}
	// EIP-55's own examples check, so the checker works.
	for _, example := range []string{"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"} {
		if !valid(example) {
			t.Fatalf("the EIP-55 checker refuses the example %s", example)
		}
	}
	if valid(Addresses[2].Text) {
		t.Errorf("%q passes its checksum, so a wallet would accept it", Addresses[2].Text)
	}
}

// keccak256 is the hash Ethereum uses: Keccak with a rate of 136 bytes and
// the padding from before SHA-3 was finished.
func keccak256(data []byte) []byte {
	const rate = 136
	msg := append(append([]byte{}, data...), 0x01)
	for len(msg)%rate != 0 {
		msg = append(msg, 0)
	}
	msg[len(msg)-1] |= 0x80
	var st [25]uint64
	for off := 0; off < len(msg); off += rate {
		for i := range rate / 8 {
			st[i] ^= binary.LittleEndian.Uint64(msg[off+8*i:])
		}
		keccakF(&st)
	}
	out := make([]byte, 32)
	for i := range 4 {
		binary.LittleEndian.PutUint64(out[8*i:], st[i])
	}
	return out
}

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rotations = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var lanes = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func keccakF(st *[25]uint64) {
	var bc [5]uint64
	for round := range 24 {
		for i := range 5 {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i := range 5 {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}
		t := st[1]
		for i := range 24 {
			j := lanes[i]
			bc[0] = st[j]
			st[j] = bits.RotateLeft64(t, rotations[i])
			t = bc[0]
		}
		for j := 0; j < 25; j += 5 {
			for i := range 5 {
				bc[i] = st[j+i]
			}
			for i := range 5 {
				st[j+i] ^= ^bc[(i+1)%5] & bc[(i+2)%5]
			}
		}
		st[0] ^= roundConstants[round]
	}
}
