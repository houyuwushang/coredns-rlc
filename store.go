package rlc

import (
	"container/list"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type observation struct {
	address netip.Addr
	name    string
	seen    time.Time
}

type nameTTL struct {
	name string
	ttl  uint32
}

// Capacity counts IP/name pairs, not IPs. Queries never extend retention.
// The list is ordered by ingestion, while expiry uses the observation time.
type store struct {
	mu        sync.Mutex
	entries   map[netip.Addr]map[string]*list.Element
	order     *list.List
	capacity  int
	maxNames  int
	retention time.Duration
	answerTTL time.Duration
}

func newStore(capacity, maxNames int, retention, answerTTL time.Duration) *store {
	return &store{
		entries: make(map[netip.Addr]map[string]*list.Element), order: list.New(),
		capacity: capacity, maxNames: maxNames, retention: retention, answerTTL: answerTTL,
	}
}

func (s *store) remove(e *list.Element) {
	o := e.Value.(observation)
	delete(s.entries[o.address], o.name)
	if len(s.entries[o.address]) == 0 {
		delete(s.entries, o.address)
	}
	s.order.Remove(e)
}

func (s *store) add(address netip.Addr, names []string, seen, now time.Time) {
	if !address.IsValid() || !seen.Add(s.retention).After(now) {
		return
	}
	if seen.After(now) {
		seen = now
	}
	address = address.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range names {
		if e := s.entries[address][name]; e != nil {
			o := e.Value.(observation)
			if seen.After(o.seen) {
				o.seen = seen
				e.Value = o
				s.order.MoveToBack(e)
			}
			continue
		}
		if len(s.entries[address]) >= s.maxNames {
			var oldest *list.Element
			for _, e := range s.entries[address] {
				o := e.Value.(observation)
				if oldest == nil || o.seen.Before(oldest.Value.(observation).seen) ||
					(o.seen.Equal(oldest.Value.(observation).seen) && o.name > oldest.Value.(observation).name) {
					oldest = e
				}
			}
			// An old replay must not displace a newer observation.
			if seen.Before(oldest.Value.(observation).seen) {
				continue
			}
			s.remove(oldest)
		}
		for s.order.Len() >= s.capacity {
			s.remove(s.order.Front())
		}
		if s.entries[address] == nil {
			s.entries[address] = make(map[string]*list.Element)
		}
		e := s.order.PushBack(observation{address: address, name: name, seen: seen})
		s.entries[address][name] = e
	}
}

func (s *store) lookup(address netip.Addr, now time.Time) []nameTTL {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []nameTTL
	for name, e := range s.entries[address.Unmap()] {
		left := e.Value.(observation).seen.Add(s.retention).Sub(now)
		if left <= 0 {
			s.remove(e)
			continue
		}
		if left > s.answerTTL {
			left = s.answerTTL
		}
		result = append(result, nameTTL{name, uint32(left / time.Second)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}
