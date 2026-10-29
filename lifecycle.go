package rlc

import (
	"context"
	"fmt"
	"net"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("rlc")

// Open every socket synchronously. A partial startup is rolled back before
// returning the error to CoreDNS; background goroutines never terminate it.
func (h *Handler) start() error {
	h.lifeMu.Lock()
	defer h.lifeMu.Unlock()
	if h.running {
		return nil
	}
	var peer, remote net.Listener
	var err error
	if h.config.peerListen != "" {
		peer, err = net.Listen("tcp", h.config.peerListen)
		if err != nil {
			return fmt.Errorf("rlc peer listener: %w", err)
		}
	}
	if h.config.remote != "" {
		remote, err = net.Listen("tcp", h.config.remote)
		if err != nil {
			if peer != nil {
				_ = peer.Close()
			}
			return fmt.Errorf("rlc dnstap listener: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.running = true
	if peer != nil {
		started := make(chan struct{})
		h.peerServer = &dns.Server{Listener: peer, Handler: dns.HandlerFunc(h.servePeer), ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, NotifyStartedFunc: func() { close(started) }}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			if err := h.peerServer.ActivateAndServe(); err != nil {
				h.ready.Store(false)
				log.Errorf("peer listener: %v", err)
			}
		}()
		<-started
	}
	if remote != nil {
		h.remoteListener = remote
		h.wg.Add(1)
		go h.acceptRemote(ctx, remote)
	}
	if h.config.discoverName != "" {
		h.wg.Add(1)
		go h.discoverLoop(ctx)
	}
	h.ready.Store(true)
	return nil
}

func (h *Handler) stop() error {
	h.lifeMu.Lock()
	defer h.lifeMu.Unlock()
	if !h.running {
		return nil
	}
	h.ready.Store(false)
	h.cancel()
	if h.remoteListener != nil {
		_ = h.remoteListener.Close()
	}
	h.connectionsMu.Lock()
	for conn := range h.connections {
		_ = conn.Close()
	}
	h.connectionsMu.Unlock()
	var err error
	if h.peerServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = h.peerServer.ShutdownContext(ctx)
		cancel()
	}
	h.wg.Wait()
	h.running = false
	h.peerServer, h.remoteListener = nil, nil
	return err
}
