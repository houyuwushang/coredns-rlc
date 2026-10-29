package rlc

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestReverseAddress(t *testing.T) {
	for _, address := range []string{"192.0.2.7", "0.0.0.0", "255.255.255.255", "2001:db8::7", "::1", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:192.0.2.7"} {
		t.Run(address, func(t *testing.T) {
			query, err := dns.ReverseAddr(address)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{query, strings.ToUpper(query)} {
				got, ok := reverseAddress(name)
				if !ok || got != netip.MustParseAddr(address).Unmap() {
					t.Fatalf("%s: %v, %v", name, got, ok)
				}
			}
		})
	}
	for _, name := range []string{"", ".", "example.org.", "7.2.0.192.in-addr.arpa", "256.2.0.192.in-addr.arpa.", "-1.2.0.192.in-addr.arpa.", "+1.2.0.192.in-addr.arpa.", "7.2.0.in-addr.arpa.", "7.2.0.192.0.in-addr.arpa.", "1..2.0.192.in-addr.arpa.", "7.0.0.0.0.0.0.0.ip6.arpa.", strings.Repeat("g.", 32) + "ip6.arpa.", strings.Repeat("00.", 32) + "ip6.arpa."} {
		if got, ok := reverseAddress(name); ok {
			t.Errorf("accepted %q as %s", name, got)
		}
	}
}

func TestCanonicalName(t *testing.T) {
	for _, pair := range [][2]string{{"WWW.Example.ORG.", "www.example.org."}, {`\119ww.example.org.`, "www.example.org."}, {"Ä.example.org.", `\195\132.example.org.`}, {`a\.b.example.org.`, `a\046b.example.org.`}} {
		a, ok := canonicalName(pair[0])
		b, bok := canonicalName(pair[1])
		if !ok || !bok || a != b {
			t.Errorf("%q != %q: %q %q", pair[0], pair[1], a, b)
		}
	}
	a, _ := canonicalName("Ä.example.org.")
	b, _ := canonicalName("ä.example.org.")
	if a == b {
		t.Fatal("Unicode case folding changed DNS octets")
	}
	for _, name := range []string{"not.absolute", strings.Repeat("a", 64) + ".org.", "bad..org."} {
		if _, ok := canonicalName(name); ok {
			t.Errorf("accepted %q", name)
		}
	}
}

func FuzzReverseAddress(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1})
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, raw []byte) {
		address, ok := netip.AddrFromSlice(raw)
		if !ok {
			return
		}
		query, err := dns.ReverseAddr(address.String())
		if err != nil {
			t.Fatal(err)
		}
		got, ok := reverseAddress(query)
		if !ok || got != address.Unmap() {
			t.Fatalf("%s -> %s", query, got)
		}
	})
}

func FuzzReverseMalformed(f *testing.F) {
	f.Add("7.2.0.192.in-addr.arpa.")
	f.Add("bad..ip6.arpa.")
	f.Fuzz(func(t *testing.T, name string) {
		if got, ok := reverseAddress(name); ok && !got.IsValid() {
			t.Fatal("invalid address accepted")
		}
	})
}
