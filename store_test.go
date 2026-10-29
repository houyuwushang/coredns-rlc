package rlc

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestRetentionAndReplay(t *testing.T) {
	now := time.Unix(10000, 0)
	ip := netip.MustParseAddr("192.0.2.7")
	s := newStore(4, 3, 10*time.Second, 5*time.Second)
	s.add(ip, []string{"first.example.org."}, now, now)
	if got := s.lookup(ip, now); len(got) != 1 || got[0].ttl != 5 {
		t.Fatal(got)
	}
	// Neither reads nor an older dnstap event renew an observation.
	for i := 1; i < 10; i++ {
		s.lookup(ip, now.Add(time.Duration(i)*time.Second))
		s.add(ip, []string{"first.example.org."}, now.Add(-time.Second), now.Add(time.Duration(i)*time.Second))
	}
	if got := s.lookup(ip, now.Add(9500*time.Millisecond)); len(got) != 1 || got[0].ttl != 0 {
		t.Fatal(got)
	}
	if got := s.lookup(ip, now.Add(10*time.Second)); len(got) != 0 {
		t.Fatal("read extended expiry", got)
	}
	s.add(ip, []string{"expired.example.org."}, now, now.Add(10*time.Second))
	if got := s.lookup(ip, now.Add(10*time.Second)); len(got) != 0 {
		t.Fatal("accepted expired replay")
	}
	s.add(ip, []string{"future.example.org."}, now.Add(time.Hour), now)
	if got := s.lookup(ip, now.Add(10*time.Second)); len(got) != 0 {
		t.Fatal("future timestamp extended retention")
	}
}

func TestCapacityBoundsNamesAndAddresses(t *testing.T) {
	now := time.Now()
	s := newStore(3, 2, time.Hour, time.Second)
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	s.add(a, []string{"a.example.org.", "b.example.org."}, now, now)
	s.add(a, []string{"c.example.org."}, now.Add(time.Second), now.Add(time.Second))
	if len(s.lookup(a, now)) != 2 || s.order.Len() != 2 {
		t.Fatal("per-address bound")
	}
	s.add(b, []string{"d.example.org.", "e.example.org."}, now.Add(2*time.Second), now.Add(2*time.Second))
	if s.order.Len() != 3 || len(s.lookup(a, now)) != 1 || len(s.lookup(b, now)) != 2 {
		t.Fatal("pair capacity not enforced")
	}
	s.lookup(a, now.Add(2*time.Hour))
	s.lookup(b, now.Add(2*time.Hour))
	if len(s.entries) != 0 || s.order.Len() != 0 {
		t.Fatal("expired entries retained after lookup")
	}
}

func TestConcurrentObservations(t *testing.T) {
	h := newHandler(defaults())
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr("192.0.2.7")
			for j := range 100 {
				now := time.Now()
				h.cache.add(ip, []string{fmt.Sprintf("n%d-%d.example.org.", i, j)}, now, now)
				h.cache.lookup(ip, now)
			}
		}()
	}
	wg.Wait()
	if h.cache.order.Len() > 16 {
		t.Fatal("per-IP memory grew beyond bound")
	}
}
