package rlc

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/miekg/dns"
)

func (h *Handler) endpoints() []string {
	h.peersMu.RLock()
	peers := append(slices.Clone(h.config.peers), h.discovered...)
	h.peersMu.RUnlock()
	sort.Strings(peers)
	peers = slices.Compact(peers)
	return peers[:min(len(peers), maxPeers)]
}

// Peers answer from their local observations only. We query all available peers
// even on a local hit, so a local subset does not hide names observed elsewhere.
// Results are not reinserted: reading from another node cannot renew retention.
func (h *Handler) lookup(ctx context.Context, address netip.Addr) []nameTTL {
	started := h.now()
	combined := make(map[string]uint32)
	peers := h.endpoints()
	if len(peers) != 0 {
		ctx, cancel := context.WithTimeout(ctx, h.config.peerTimeout)
		defer cancel()
		results := make(chan []nameTTL, len(peers))
		query, _ := dns.ReverseAddr(address.String())
		pending := 0
		for _, peer := range peers {
			select {
			case h.peerSlots <- struct{}{}:
				pending++
				go func() {
					defer func() { <-h.peerSlots }()
					results <- h.askPeer(ctx, peer, query)
				}()
			default: // Keep both goroutine count and upstream work bounded.
			}
		}
		for pending > 0 {
			select {
			case names := <-results:
				pending--
				for _, n := range names {
					if ttl, exists := combined[n.name]; !exists || n.ttl < ttl {
						combined[n.name] = n.ttl
					}
				}
			case <-ctx.Done():
				pending = 0
			}
		}
	}
	// Do not advertise a TTL longer than the data's lifetime after peer latency.
	elapsed := h.now().Sub(started)
	for name, ttl := range combined {
		left := time.Duration(ttl)*time.Second - elapsed
		if ttl != 0 && left <= 0 {
			delete(combined, name)
			continue
		}
		if left < 0 {
			left = 0
		}
		combined[name] = uint32(left / time.Second)
	}
	// Check local expiry after waiting, rather than returning an expired snapshot.
	for _, n := range h.cache.lookup(address, h.now()) {
		if ttl, exists := combined[n.name]; !exists || n.ttl < ttl {
			combined[n.name] = n.ttl
		}
	}
	result := make([]nameTTL, 0, len(combined))
	for name, ttl := range combined {
		result = append(result, nameTTL{name, ttl})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result[:min(len(result), h.config.maxNames)]
}

func (h *Handler) askPeer(ctx context.Context, peer, query string) []nameTTL {
	r := new(dns.Msg)
	r.SetQuestion(query, dns.TypePTR)
	r.RecursionDesired = false
	client := dns.Client{Net: "tcp", Timeout: h.config.peerTimeout}
	m, _, err := client.ExchangeContext(ctx, r, peer)
	if err != nil || m == nil || !m.Response || m.Rcode != dns.RcodeSuccess || m.Truncated || len(m.Question) != 1 || m.Question[0] != r.Question[0] || m.AuthenticatedData {
		return nil
	}
	if len(m.Answer) > 128 {
		return nil
	}
	var names []nameTTL
	for _, rr := range m.Answer {
		ptr, ok := rr.(*dns.PTR)
		if !ok || ptr.Hdr.Class != dns.ClassINET {
			return nil
		}
		owner, ok := canonicalName(ptr.Hdr.Name)
		if !ok || owner != query {
			return nil
		}
		name, ok := canonicalName(ptr.Ptr)
		if !ok {
			return nil
		}
		ttl := min(ptr.Hdr.Ttl, uint32(h.config.answerTTL/time.Second))
		names = append(names, nameTTL{name, ttl})
	}
	return names
}

func (h *Handler) servePeer(w dns.ResponseWriter, r *dns.Msg) {
	if eligible(r) && r.Question[0].Qtype == dns.TypePTR {
		if address, ok := reverseAddress(r.Question[0].Name); ok {
			_ = writeAnswer(w, r, localNames(h, address))
			return
		}
	}
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}

func (h *Handler) discover(ctx context.Context) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, h.config.discoverResolver)
	}}
	ctx, cancel := context.WithTimeout(ctx, h.config.peerTimeout)
	defer cancel()
	addresses, err := resolver.LookupNetIP(ctx, "ip", h.config.discoverName)
	if err != nil {
		// Failed discovery must not keep contacting removed nodes indefinitely.
		addresses = nil
	}
	var peers []string
	for _, address := range addresses {
		if address.IsValid() && !address.IsUnspecified() && address.Zone() == "" {
			peers = append(peers, netip.AddrPortFrom(address.Unmap(), h.config.discoverPort).String())
		}
	}
	sort.Strings(peers)
	peers = slices.Compact(peers)
	if len(peers) > maxPeers {
		peers = peers[:maxPeers]
	}
	h.peersMu.Lock()
	h.discovered = peers
	h.peersMu.Unlock()
}

func (h *Handler) discoverLoop(ctx context.Context) {
	defer h.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		h.discover(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
