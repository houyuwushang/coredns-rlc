package rlc

import (
	"sync"

	"github.com/coredns/caddy"
)

type ownerKey struct{}
type instanceOwner struct{ marker byte }

var ownership = struct {
	sync.Mutex
	handlers map[*Handler]*instanceOwner
}{handlers: make(map[*Handler]*instanceOwner)}

// Caddy 1 runs startup callbacks before opening the DNS listeners. If that
// later step fails during reload, it discards the new instance without running
// its shutdown callbacks. Reap only our discarded instances before restoring
// the old instance, including when the new configuration changed port numbers.
func reapDiscarded() {
	live := make(map[*instanceOwner]bool)
	for _, instance := range caddy.Instances() {
		instance.StorageMu.RLock()
		owner, _ := instance.Storage[ownerKey{}].(*instanceOwner)
		instance.StorageMu.RUnlock()
		live[owner] = true
	}
	ownership.Lock()
	var discarded []*Handler
	for h, owner := range ownership.handlers {
		if !live[owner] {
			discarded = append(discarded, h)
		}
	}
	ownership.Unlock()
	for _, h := range discarded {
		_ = stopOwned(h)
	}
}

func startOwned(h *Handler, owner *instanceOwner) error {
	reapDiscarded()
	if err := h.start(); err != nil {
		return err
	}
	ownership.Lock()
	ownership.handlers[h] = owner
	ownership.Unlock()
	return nil
}

func stopOwned(h *Handler) error {
	err := h.stop()
	ownership.Lock()
	delete(ownership.handlers, h)
	ownership.Unlock()
	return err
}
