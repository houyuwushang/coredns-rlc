package rlc

import (
	"net"
	"net/netip"
	"testing"
	"time"

	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func tapFrame(t *testing.T, typ tap.Message_Type, seen time.Time) *tap.Dnstap {
	t.Helper()
	m := answer(t, question("www.example.org.", dns.TypeAAAA), "www.example.org. 1 IN AAAA 2001:db8::7")
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &tap.Dnstap{Type: tap.Dnstap_MESSAGE.Enum(), Message: &tap.Message{Type: typ.Enum(), ResponseMessage: wire, ResponseTimeSec: proto.Uint64(uint64(seen.Unix())), ResponseTimeNsec: proto.Uint32(uint32(seen.Nanosecond()))}}
}

func TestDnstapUsesResponseAndEventTime(t *testing.T) {
	now := time.Now()
	h := newHandler(defaults())
	h.now = func() time.Time { return now }
	for _, bad := range []string{"query", "query-field", "malformed", "expired", "bad-nsec", "bad-time", "empty"} {
		t.Run(bad, func(t *testing.T) {
			e := tapFrame(t, tap.Message_CLIENT_RESPONSE, now)
			switch bad {
			case "query":
				e.Message.Type = tap.Message_CLIENT_QUERY.Enum()
			case "query-field":
				e.Message.QueryMessage = e.Message.ResponseMessage
				e.Message.ResponseMessage = nil
			case "malformed":
				e.Message.ResponseMessage = []byte{1, 2, 3}
			case "expired":
				e.Message.ResponseTimeSec = proto.Uint64(uint64(now.Add(-2 * time.Hour).Unix()))
			case "bad-nsec":
				e.Message.ResponseTimeNsec = proto.Uint32(1000000000)
			case "bad-time":
				e.Message.ResponseTimeSec = proto.Uint64(^uint64(0))
			case "empty":
				e.Message = nil
			}
			b, err := proto.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			h.ingest(b)
			if h.cache.order.Len() != 0 {
				t.Fatal("invalid event learned")
			}
		})
	}
	h.ingest([]byte{255, 255})
	e := tapFrame(t, tap.Message_CLIENT_RESPONSE, now.Add(-30*time.Minute))
	b, _ := proto.Marshal(e)
	h.ingest(b)
	if got := h.cache.lookup(netip.MustParseAddr("2001:db8::7"), now); len(got) != 1 {
		t.Fatal(got)
	}
	if got := h.cache.lookup(netip.MustParseAddr("2001:db8::7"), now.Add(31*time.Minute)); len(got) != 0 {
		t.Fatal("event aged from ingestion, not event time")
	}
}

func TestRealDnstapStreamAndShutdown(t *testing.T) {
	cfg := defaults()
	cfg.remote = "127.0.0.1:0"
	h := newHandler(cfg)
	if err := h.start(); err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	conn, err := net.DialTimeout("tcp", h.remoteListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writer, err := tap.NewWriter(conn, &tap.WriterOptions{Bidirectional: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e := tapFrame(t, tap.Message_FORWARDER_RESPONSE, time.Now())
	b, err := proto.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.WriteFrame(b); err != nil {
		t.Fatal(err)
	}
	if err = writer.(interface{ Flush() error }).Flush(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(h.cache.lookup(netip.MustParseAddr("2001:db8::7"), time.Now())) == 1 })
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	// An incomplete handshake must not block shutdown or a later connection.
	idle, err := net.DialTimeout("tcp", h.remoteListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	start := time.Now()
	if err = h.stop(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("shutdown waited for an idle dnstap peer")
	}
	if h.Ready() {
		t.Fatal("ready after stop")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestListenerFailureRollbackAndRestart(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := defaults()
	cfg.peerListen = "127.0.0.1:0"
	cfg.remote = busy.Addr().String()
	h := newHandler(cfg)
	if err = h.start(); err == nil {
		h.stop()
		t.Fatal("ignored occupied dnstap port")
	}
	if h.Ready() || h.running {
		t.Fatal("partial start marked ready")
	}
	h.config.remote = "127.0.0.1:0"
	for range 3 {
		if err = h.start(); err != nil {
			t.Fatal(err)
		}
		if !h.Ready() {
			t.Fatal("not ready after startup")
		}
		if err = h.start(); err != nil {
			t.Fatal("start was not idempotent", err)
		}
		if err = h.stop(); err != nil {
			t.Fatal(err)
		}
		if err = h.stop(); err != nil {
			t.Fatal("stop was not idempotent", err)
		}
	}
}
