package rlc

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// canonicalName compares DNS octets, including equivalent escaped spellings.
// Unicode case folding would change DNS names, so only ASCII A-Z is folded.
func canonicalName(name string) (string, bool) {
	if !dns.IsFqdn(name) {
		return "", false
	}
	var buf [256]byte
	n, err := dns.PackDomainName(name, buf[:], 0, nil, false)
	if err != nil || n > 255 {
		return "", false
	}
	for i := 0; i < n && buf[i] != 0; {
		end := i + 1 + int(buf[i])
		for j := i + 1; j < end; j++ {
			if buf[j] >= 'A' && buf[j] <= 'Z' {
				buf[j] += 'a' - 'A'
			}
		}
		i = end
	}
	result, _, err := dns.UnpackDomainName(buf[:n], 0)
	return result, err == nil
}

func reverseAddress(name string) (netip.Addr, bool) {
	name, ok := canonicalName(name)
	if !ok {
		return netip.Addr{}, false
	}
	labels := strings.Split(name, ".")
	if len(labels) == 7 && labels[4] == "in-addr" && labels[5] == "arpa" {
		var addr [4]byte
		for i := range 4 {
			part := labels[i]
			if len(part) == 0 || len(part) > 3 {
				return netip.Addr{}, false
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					return netip.Addr{}, false
				}
			}
			v, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return netip.Addr{}, false
			}
			addr[3-i] = byte(v)
		}
		return netip.AddrFrom4(addr), true
	}
	if len(labels) == 35 && labels[32] == "ip6" && labels[33] == "arpa" {
		var digits [32]byte
		for i := range 32 {
			if len(labels[i]) != 1 {
				return netip.Addr{}, false
			}
			digits[31-i] = labels[i][0]
		}
		var addr [16]byte
		if _, err := hex.Decode(addr[:], digits[:]); err != nil {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16(addr).Unmap(), true
	}
	return netip.Addr{}, false
}
