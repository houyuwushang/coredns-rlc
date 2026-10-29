package rlc

import (
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// learn follows only the queried CNAME chain. Unrelated answer/additional
// addresses, ambiguous aliases, loops and incomplete answers cannot seed it.
func (h *Handler) learn(m *dns.Msg, seen time.Time) {
	if !m.Response || m.Opcode != dns.OpcodeQuery || m.Rcode != dns.RcodeSuccess || m.Truncated || len(m.Question) != 1 {
		return
	}
	q := m.Question[0]
	if q.Qclass != dns.ClassINET || (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		return
	}
	name, ok := canonicalName(q.Name)
	if !ok {
		return
	}
	aliases := make(map[string]string)
	addresses := make(map[string][]netip.Addr)
	for _, rr := range m.Answer {
		if rr.Header().Class != dns.ClassINET {
			continue
		}
		owner, ok := canonicalName(rr.Header().Name)
		if !ok {
			return
		}
		switch r := rr.(type) {
		case *dns.CNAME:
			target, ok := canonicalName(r.Target)
			if !ok || (aliases[owner] != "" && aliases[owner] != target) {
				return
			}
			aliases[owner] = target
		case *dns.A:
			if q.Qtype == dns.TypeA {
				if addr, ok := netip.AddrFromSlice(r.A.To4()); ok {
					addresses[owner] = append(addresses[owner], addr)
				}
			}
		case *dns.AAAA:
			if q.Qtype == dns.TypeAAAA && len(r.AAAA) == 16 {
				if addr, ok := netip.AddrFromSlice(r.AAAA); ok {
					addresses[owner] = append(addresses[owner], addr.Unmap())
				}
			}
		}
	}
	visited := make(map[string]bool)
	var names []string
	for len(names) < 64 {
		if visited[name] {
			return
		}
		visited[name] = true
		names = append(names, name)
		if target := aliases[name]; target != "" {
			if len(addresses[name]) != 0 {
				return // CNAME and address data at the same owner are ambiguous.
			}
			name = target
			continue
		}
		now := h.now()
		for _, address := range addresses[name] {
			h.cache.add(address, names, seen, now)
		}
		return
	}
}
