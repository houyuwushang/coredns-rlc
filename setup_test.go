package rlc

import (
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func TestParse(t *testing.T) {
	cfg, err := parse(caddy.NewTestController("dns", `rlc {
 ttl 120
 answer_ttl 3s
 capacity 100
 max_names 8
 peer_listen 127.0.0.1:8054
 peers 192.0.2.1:8054 [2001:db8::1]:8054
 peer_timeout 50ms
 discover rlc-peers.example.org. 8054 127.0.0.1:53
 remote 127.0.0.1:8053
}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.retention != 120*time.Second || cfg.answerTTL != 3*time.Second || cfg.capacity != 100 || cfg.maxNames != 8 || len(cfg.peers) != 2 || cfg.discoverPort != 8054 {
		t.Fatal(cfg)
	}
	for _, input := range []string{
		"rlc extra", "rlc\nrlc", "rlc {\n bogus value\n}",
		"rlc {\n ttl 1s\n ttl 2s\n}", "rlc {\n ttl 0\n}", "rlc {\n ttl -1s\n}", "rlc {\n ttl 999999999999999999999\n}", "rlc {\n ttl 1s extra\n}",
		"rlc {\n capacity 0\n}", "rlc {\n capacity 1000001\n}", "rlc {\n max_names 129\n}", "rlc {\n peer_timeout 3s\n}",
		"rlc {\n peers\n}", "rlc {\n peers example.org:53\n}", "rlc {\n peers 0.0.0.0:53\n}", "rlc {\n peers 127.0.0.1:0\n}",
		"rlc {\n peer_listen 8054\n}", "rlc {\n remote\n}", "rlc {\n discover name.example.org 8054 127.0.0.1:53\n}", "rlc {\n discover example.org. 0 127.0.0.1:53\n}",
	} {
		if _, err := parse(caddy.NewTestController("dns", input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}
