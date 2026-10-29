package rlc

import (
	"context"
	"net"
	"time"

	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func (h *Handler) acceptRemote(ctx context.Context, listener net.Listener) {
	defer h.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				h.ready.Store(false)
				log.Errorf("dnstap listener: %v", err)
			}
			return
		}
		h.connectionsMu.Lock()
		if ctx.Err() != nil || len(h.connections) >= 16 {
			h.connectionsMu.Unlock()
			_ = conn.Close()
			continue
		}
		h.connections[conn] = struct{}{}
		h.wg.Add(1)
		h.connectionsMu.Unlock()
		go h.readRemote(conn)
	}
}

func (h *Handler) readRemote(conn net.Conn) {
	defer h.wg.Done()
	defer func() {
		_ = conn.Close()
		h.connectionsMu.Lock()
		delete(h.connections, conn)
		h.connectionsMu.Unlock()
	}()
	reader, err := tap.NewReader(conn, &tap.ReaderOptions{Bidirectional: true, Timeout: 2 * time.Second})
	if err != nil {
		return
	}
	buf := make([]byte, 128*1024)
	for {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
		n, err := reader.ReadFrame(buf)
		if err != nil {
			return
		}
		h.ingest(buf[:n])
	}
}

func (h *Handler) ingest(frame []byte) {
	var event tap.Dnstap
	if proto.Unmarshal(frame, &event) != nil || event.GetType() != tap.Dnstap_MESSAGE || event.Message == nil {
		return
	}
	m := event.Message
	switch m.GetType() {
	case tap.Message_AUTH_RESPONSE, tap.Message_CLIENT_RESPONSE, tap.Message_RESOLVER_RESPONSE, tap.Message_FORWARDER_RESPONSE, tap.Message_STUB_RESPONSE, tap.Message_TOOL_RESPONSE:
	default:
		return
	}
	response := new(dns.Msg)
	if len(m.ResponseMessage) == 0 || response.Unpack(m.ResponseMessage) != nil {
		return
	}
	seen := h.now()
	if m.ResponseTimeSec != nil {
		// Reject values outside time.Time's useful range and invalid nanoseconds.
		if m.GetResponseTimeSec() > 253402300799 || m.GetResponseTimeNsec() >= 1000000000 {
			return
		}
		seen = time.Unix(int64(m.GetResponseTimeSec()), int64(m.GetResponseTimeNsec()))
	}
	h.learn(response, seen)
}
