package rlc

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startPeer(t *testing.T) *Handler {
	t.Helper()
	cfg := defaults()
	cfg.peerListen = "127.0.0.1:0"
	h := newHandler(cfg)
	if err := h.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.stop(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func TestRealPeerLookupUnionAndExpiry(t *testing.T) {
	peer := startPeer(t)
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	peer.now = func() time.Time { return time.Unix(0, clock.Load()) }
	for _, ip := range []string{"192.0.2.7", "2001:db8::7"} {
		now := peer.now()
		peer.cache.add(netip.MustParseAddr(ip), []string{"a.example.org.", "shared.example.org."}, now, now)
	}
	cfg := defaults()
	cfg.peers = []string{peer.peerServer.Listener.Addr().String()}
	h := newHandler(cfg)
	for _, ip := range []string{"192.0.2.7", "2001:db8::7"} {
		now := time.Now()
		h.cache.add(netip.MustParseAddr(ip), []string{"b.example.org.", "shared.example.org."}, now, now)
		q, _ := dns.ReverseAddr(ip)
		w := &recorder{}
		if _, err := h.ServeDNS(context.Background(), w, question(q, dns.TypePTR)); err != nil {
			t.Fatal(err)
		}
		if got := namesOf(w.msg); !reflect.DeepEqual(got, []string{"a.example.org.", "b.example.org.", "shared.example.org."}) {
			t.Fatal(got)
		}
	}
	if h.cache.order.Len() != 4 {
		t.Fatal("peer results were copied into local cache")
	}
	clock.Add(int64(2 * time.Hour))
	got := h.lookup(context.Background(), netip.MustParseAddr("192.0.2.7"))
	if len(got) != 2 || got[0].name != "b.example.org." {
		t.Fatal("peer reads renewed expiry", got)
	}
}

func tcpDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	s := &dns.Server{Listener: l, Handler: handler, ReadTimeout: time.Second, WriteTimeout: time.Second, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		s.Shutdown()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return l.Addr().String()
}

func TestPeerDoesNotRecurse(t *testing.T) {
	var calls atomic.Int64
	address := tcpDNS(t, func(w dns.ResponseWriter, r *dns.Msg) { calls.Add(1); m := new(dns.Msg); m.SetReply(r); w.WriteMsg(m) })
	cfg := defaults()
	cfg.peerListen = "127.0.0.1:0"
	cfg.peers = []string{address}
	h := newHandler(cfg)
	if err := h.start(); err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	q := question("7.2.0.192.in-addr.arpa.", dns.TypePTR)
	c := dns.Client{Net: "tcp", Timeout: time.Second}
	m, _, err := c.Exchange(q, h.peerServer.Listener.Addr().String())
	if err != nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || calls.Load() != 0 {
		t.Fatalf("%v %v calls=%d", m, err, calls.Load())
	}
}

func TestPeerResponseValidation(t *testing.T) {
	for _, kind := range []string{"wrong-owner", "wrong-question", "wrong-class", "wrong-type", "error", "truncated", "authenticated"} {
		t.Run(kind, func(t *testing.T) {
			address := tcpDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
				m := answer(t, r, "7.2.0.192.in-addr.arpa. 999 IN PTR www.example.org.")
				switch kind {
				case "wrong-owner":
					m.Answer[0].Header().Name = "8.2.0.192.in-addr.arpa."
				case "wrong-question":
					m.Question[0].Name = "8.2.0.192.in-addr.arpa."
				case "wrong-class":
					m.Answer[0].Header().Class = dns.ClassCHAOS
				case "wrong-type":
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 0, 2, 7)}}
				case "error":
					m.Rcode = dns.RcodeNameError
				case "truncated":
					m.Truncated = true
				case "authenticated":
					m.AuthenticatedData = true
				}
				w.WriteMsg(m)
			})
			h := newHandler(defaults())
			if got := h.askPeer(context.Background(), address, "7.2.0.192.in-addr.arpa."); len(got) != 0 {
				t.Fatal(got)
			}
		})
	}
}

func TestPeerDeadlineCancellationAndSaturation(t *testing.T) {
	address := tcpDNS(t, func(w dns.ResponseWriter, r *dns.Msg) { /* Deliberately no answer. */ })
	cfg := defaults()
	cfg.peers = []string{address}
	cfg.peerTimeout = 30 * time.Millisecond
	h := newHandler(cfg)
	ip := netip.MustParseAddr("192.0.2.7")
	now := time.Now()
	h.cache.add(ip, []string{"local.example.org."}, now, now)
	start := time.Now()
	if got := h.lookup(context.Background(), ip); len(got) != 1 {
		t.Fatal(got)
	}
	if time.Since(start) > time.Second {
		t.Fatal("peer timeout was not bounded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.ServeDNS(ctx, &recorder{}, question("7.2.0.192.in-addr.arpa.", dns.TypePTR)); err != context.Canceled {
		t.Fatal(err)
	}
	// Full outbound budget must preserve the local result without launching work.
	waitFor(t, func() bool { return len(h.peerSlots) == 0 })
	for range cap(h.peerSlots) {
		h.peerSlots <- struct{}{}
	}
	if got := h.lookup(context.Background(), ip); len(got) != 1 {
		t.Fatal(got)
	}
	for range cap(h.peerSlots) {
		<-h.peerSlots
	}
}

func TestLocalExpiryDuringPeerRequest(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	address := tcpDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		clock.Add(int64(2 * time.Second))
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})
	cfg := defaults()
	cfg.retention = time.Second
	cfg.peers = []string{address}
	h := newHandler(cfg)
	h.now = func() time.Time { return time.Unix(0, clock.Load()) }
	ip := netip.MustParseAddr("192.0.2.7")
	h.cache.add(ip, []string{"expired.example.org."}, h.now(), h.now())
	if got := h.lookup(context.Background(), ip); len(got) != 0 {
		t.Fatal("returned an observation that expired while waiting for peers", got)
	}
}

func TestHeadlessDNSDiscovery(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	ready := make(chan struct{})
	done := make(chan error, 1)
	s := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if fail.Load() {
			m.Rcode = dns.RcodeNameError
		} else if r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(192, 0, 2, 7)}}
		} else {
			m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30}, AAAA: net.ParseIP("2001:db8::7")}}
		}
		w.WriteMsg(m)
	})}
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	defer func() {
		s.Shutdown()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	cfg := defaults()
	cfg.discoverName = "rlc-peers.example.org."
	cfg.discoverPort = 8054
	cfg.discoverResolver = packet.LocalAddr().String()
	cfg.peerTimeout = time.Second
	h := newHandler(cfg)
	h.discover(context.Background())
	if got := h.endpoints(); !reflect.DeepEqual(got, []string{"192.0.2.7:8054", "[2001:db8::7]:8054"}) {
		t.Fatal(got)
	}
	fail.Store(true)
	h.discover(context.Background())
	if len(h.endpoints()) != 0 {
		t.Fatal("retained removed nodes")
	}
	for i := range 40 {
		h.discovered = append(h.discovered, net.JoinHostPort("192.0.2."+strconv.Itoa(i+1), "8054"))
	}
	if len(h.endpoints()) != maxPeers {
		t.Fatal("unbounded peer set")
	}
}
