// Package rlc implements an opt-in, observation-based reverse lookup cache.
package rlc

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// Handler learns forward answers and serves synthetic PTR records.
type Handler struct {
	Next           plugin.Handler
	cache          *store
	now            func() time.Time
	config         config
	peerSlots      chan struct{}
	peersMu        sync.RWMutex
	discovered     []string
	lifeMu         sync.Mutex
	running        bool
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	peerServer     *dns.Server
	remoteListener net.Listener
	connectionsMu  sync.Mutex
	connections    map[net.Conn]struct{}
	ready          atomic.Bool
}

func newHandler(c config) *Handler {
	return &Handler{
		config: c, cache: newStore(c.capacity, c.maxNames, c.retention, c.answerTTL),
		now: time.Now, peerSlots: make(chan struct{}, 64), connections: make(map[net.Conn]struct{}),
	}
}

func (*Handler) Name() string { return "rlc" }

// Ready implements the CoreDNS ready plugin interface.
func (h *Handler) Ready() bool { return h.ready.Load() }

func eligible(r *dns.Msg) bool {
	return !r.Response && r.Opcode == dns.OpcodeQuery && len(r.Question) == 1 && r.Question[0].Qclass == dns.ClassINET && r.IsTsig() == nil
}

func (h *Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if !eligible(r) {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}
	q := r.Question[0]
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, &observer{ResponseWriter: w, handler: h, query: r.Copy()}, r)
	case dns.TypePTR:
		if opt := r.IsEdns0(); opt != nil && opt.Do() {
			break // Synthetic data cannot satisfy DNSSEC requests.
		}
		if address, ok := reverseAddress(q.Name); ok {
			names := h.lookup(ctx, address)
			if err := ctx.Err(); err != nil {
				return dns.RcodeServerFailure, err
			}
			if len(names) != 0 {
				return dns.RcodeSuccess, writeAnswer(w, r, names)
			}
		}
	}
	return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
}

func writeAnswer(w dns.ResponseWriter, r *dns.Msg, names []nameTTL) error {
	m := new(dns.Msg)
	m.SetReply(r)
	// AA and AD stay clear: these are observations, not authoritative data.
	for _, n := range names {
		m.Answer = append(m.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: n.ttl}, Ptr: n.name})
	}
	size := uint16(dns.MinMsgSize)
	if opt := r.IsEdns0(); opt != nil {
		size = max(size, min(opt.UDPSize(), 1232))
		m.SetEdns0(size, false)
	}
	if strings.HasPrefix(w.LocalAddr().Network(), "udp") {
		m.Truncate(int(size))
	}
	return w.WriteMsg(m)
}

type observer struct {
	dns.ResponseWriter
	handler *Handler
	query   *dns.Msg
}

func (w *observer) observe(m *dns.Msg) {
	if len(m.Question) != 1 || m.Id != w.query.Id {
		return
	}
	q, r := w.query.Question[0], m.Question[0]
	qn, ok := canonicalName(q.Name)
	rn, rok := canonicalName(r.Name)
	if ok && rok && qn == rn && q.Qtype == r.Qtype && q.Qclass == r.Qclass {
		w.handler.learn(m, w.handler.now())
	}
}

func (w *observer) WriteMsg(m *dns.Msg) error {
	err := w.ResponseWriter.WriteMsg(m)
	if err == nil {
		w.observe(m)
	}
	return err
}

func (w *observer) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil && n == len(data) {
		m := new(dns.Msg)
		if m.Unpack(data) == nil {
			w.observe(m)
		}
	}
	return n, err
}

func localNames(h *Handler, address netip.Addr) []nameTTL {
	return h.cache.lookup(address, h.now())
}
