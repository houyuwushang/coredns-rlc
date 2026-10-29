package rlc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type recorder struct {
	msg     *dns.Msg
	network string
	fail    bool
}

func (r *recorder) LocalAddr() net.Addr {
	if r.network == "udp" {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (r *recorder) RemoteAddr() net.Addr { return r.LocalAddr() }
func (r *recorder) WriteMsg(m *dns.Msg) error {
	if r.fail {
		return errors.New("write failed")
	}
	r.msg = m.Copy()
	return nil
}
func (r *recorder) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	return len(b), r.WriteMsg(m)
}
func (*recorder) Close() error        { return nil }
func (*recorder) TsigStatus() error   { return nil }
func (*recorder) TsigTimersOnly(bool) {}
func (*recorder) Hijack()             {}

func question(name string, typ uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, typ)
	return m
}
func answer(t *testing.T, q *dns.Msg, records ...string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(q)
	for _, s := range records {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}
func namesOf(m *dns.Msg) []string {
	var result []string
	for _, rr := range m.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			result = append(result, p.Ptr)
		}
	}
	return result
}

func TestLearnCNAMEChainAndIgnoreUnrelatedData(t *testing.T) {
	for _, tc := range []struct {
		typ        uint16
		ip, record string
	}{{dns.TypeA, "192.0.2.7", "edge.example.org. 1 IN A 192.0.2.7"}, {dns.TypeAAAA, "2001:db8::7", "edge.example.org. 1 IN AAAA 2001:db8::7"}} {
		h := newHandler(defaults())
		q := question("WWW.Example.ORG.", tc.typ)
		m := answer(t, q, "www.example.org. 1 IN CNAME alias.example.org.", "alias.example.org. 1 IN CNAME edge.example.org.", tc.record, "unrelated.example.org. 1 IN A 198.51.100.1")
		m.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "evil.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.2")}}
		before, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		h.learn(m, time.Now())
		got := h.cache.lookup(netip.MustParseAddr(tc.ip), time.Now())
		var names []string
		for _, n := range got {
			names = append(names, n.name)
		}
		if !reflect.DeepEqual(names, []string{"alias.example.org.", "edge.example.org.", "www.example.org."}) {
			t.Fatal(names)
		}
		for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
			if len(h.cache.lookup(netip.MustParseAddr(ip), time.Now())) != 0 {
				t.Fatal("unrelated address learned")
			}
		}
		after, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("source message mutated")
		}
	}
}

func TestDoNotLearnInvalidAnswers(t *testing.T) {
	q := question("www.example.org.", dns.TypeA)
	base := answer(t, q, "www.example.org. 60 IN A 192.0.2.7")
	mutations := map[string]func(*dns.Msg){
		"query": func(m *dns.Msg) { m.Response = false }, "rcode": func(m *dns.Msg) { m.Rcode = dns.RcodeNameError }, "truncated": func(m *dns.Msg) { m.Truncated = true },
		"update": func(m *dns.Msg) { m.Opcode = dns.OpcodeUpdate }, "no-question": func(m *dns.Msg) { m.Question = nil }, "multi-question": func(m *dns.Msg) { m.Question = append(m.Question, m.Question[0]) },
		"class": func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }, "qtype": func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeMX },
		"rrclass": func(m *dns.Msg) { m.Answer[0].Header().Class = dns.ClassCHAOS }, "wrong-owner": func(m *dns.Msg) { m.Answer[0].Header().Name = "different.example.org." },
		"loop": func(m *dns.Msg) {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: q.Question[0].Name})
		},
		"ambiguous": func(m *dns.Msg) {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "other.example.org."})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			h := newHandler(defaults())
			m := base.Copy()
			mutate(m)
			h.learn(m, time.Now())
			if h.cache.order.Len() != 0 {
				t.Fatal("learned invalid response")
			}
		})
	}
}

func TestServeDNSAndObserver(t *testing.T) {
	for _, raw := range []bool{false, true} {
		h := newHandler(defaults())
		calls := 0
		h.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
			calls++
			m := answer(t, r, "www.example.org. 1 IN A 192.0.2.7")
			if raw {
				b, e := m.Pack()
				if e != nil {
					t.Fatal(e)
				}
				_, e = w.Write(b)
				return 0, e
			}
			return 0, w.WriteMsg(m)
		})
		q := question("www.example.org.", dns.TypeA)
		w := &recorder{}
		if _, err := h.ServeDNS(context.Background(), w, q); err != nil {
			t.Fatal(err)
		}
		ptr := question("7.2.0.192.in-addr.arpa.", dns.TypePTR)
		ptr.AuthenticatedData = true
		w = &recorder{}
		code, err := h.ServeDNS(context.Background(), w, ptr)
		if err != nil || code != 0 || calls != 1 || !reflect.DeepEqual(namesOf(w.msg), []string{"www.example.org."}) || w.msg.AuthenticatedData || w.msg.Authoritative {
			t.Fatalf("%d %v %d %v", code, err, calls, w.msg)
		}
	}
}

func TestBypassAndMismatchedResponses(t *testing.T) {
	h := newHandler(defaults())
	now := time.Now()
	h.cache.add(netip.MustParseAddr("192.0.2.7"), []string{"www.example.org."}, now, now)
	calls := 0
	h.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		calls++
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		return 0, w.WriteMsg(m)
	})
	base := question("7.2.0.192.in-addr.arpa.", dns.TypePTR)
	variants := []*dns.Msg{question("8.2.0.192.in-addr.arpa.", dns.TypePTR), question("not-reverse.example.org.", dns.TypePTR), question("example.org.", dns.TypeTXT)}
	do := base.Copy()
	do.SetEdns0(1232, true)
	variants = append(variants, do)
	chaos := base.Copy()
	chaos.Question[0].Qclass = dns.ClassCHAOS
	variants = append(variants, chaos)
	update := base.Copy()
	update.Opcode = dns.OpcodeUpdate
	variants = append(variants, update)
	tsig := base.Copy()
	tsig.SetTsig("key.example.org.", dns.HmacSHA256, 300, now.Unix())
	variants = append(variants, tsig)
	for _, q := range variants {
		w := &recorder{}
		h.ServeDNS(context.Background(), w, q)
		if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
			t.Fatalf("did not pass through: %v", q)
		}
	}
	if calls != len(variants) {
		t.Fatal(calls)
	}
	for _, mutate := range []func(*dns.Msg){func(m *dns.Msg) { m.Id++ }, func(m *dns.Msg) { m.Question[0].Name = "different.example.org." }, func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }} {
		x := newHandler(defaults())
		q := question("www.example.org.", dns.TypeA)
		m := answer(t, q, "www.example.org. 60 IN A 192.0.2.7")
		mutate(m)
		(&observer{ResponseWriter: &recorder{}, handler: x, query: q}).WriteMsg(m)
		if x.cache.order.Len() != 0 {
			t.Fatal("mismatched response learned")
		}
	}
}

func TestWireTruncationAndWriteError(t *testing.T) {
	var names []nameTTL
	for i := range 16 {
		names = append(names, nameTTL{strings.Repeat(string(rune('a'+i)), 50) + ".example.org.", 5})
	}
	q := question("7.2.0.192.in-addr.arpa.", dns.TypePTR)
	u := &recorder{network: "udp"}
	if err := writeAnswer(u, q, names); err != nil {
		t.Fatal(err)
	}
	packed, err := u.msg.Pack()
	if err != nil || len(packed) > 512 || !u.msg.Truncated {
		t.Fatalf("UDP size=%d TC=%v err=%v", len(packed), u.msg.Truncated, err)
	}
	tcp := &recorder{}
	writeAnswer(tcp, q, names)
	if tcp.msg.Truncated || len(tcp.msg.Answer) != 16 {
		t.Fatal(tcp.msg)
	}
	h := newHandler(defaults())
	now := time.Now()
	h.cache.add(netip.MustParseAddr("192.0.2.7"), []string{"www.example.org."}, now, now)
	if _, err := h.ServeDNS(context.Background(), &recorder{fail: true}, q); err == nil {
		t.Fatal("lost client write error")
	}
}
