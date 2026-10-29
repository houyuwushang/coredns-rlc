package rlc

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const maxPeers = 32

type config struct {
	retention        time.Duration
	answerTTL        time.Duration
	capacity         int
	maxNames         int
	peerListen       string
	peers            []string
	peerTimeout      time.Duration
	discoverName     string
	discoverPort     uint16
	discoverResolver string
	remote           string
}

func defaults() config {
	return config{retention: time.Hour, answerTTL: 5 * time.Second, capacity: 10000, maxNames: 16, peerTimeout: 200 * time.Millisecond}
}

func init() { plugin.Register("rlc", setup) }

func setup(c *caddy.Controller) error {
	cfg, err := parse(c)
	if err != nil {
		return plugin.Error("rlc", err)
	}
	if a, b := slices.Index(dnsserver.Directives, "rlc"), slices.Index(dnsserver.Directives, "cache"); a >= 0 && b >= 0 && a > b {
		return plugin.Error("rlc", fmt.Errorf("rlc must precede cache in the compiled plugin order (plugin.cfg)"))
	}
	h := newHandler(cfg)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})
	owner, _ := c.Get(ownerKey{}).(*instanceOwner)
	if owner == nil {
		owner = new(instanceOwner)
		c.Set(ownerKey{}, owner)
	}
	c.OnStartup(func() error { return startOwned(h, owner) })
	c.OnRestart(func() error { return stopOwned(h) })
	c.OnRestartFailed(func() error { return startOwned(h, owner) })
	c.OnFinalShutdown(func() error { return stopOwned(h) })
	return nil
}

func parse(c *caddy.Controller) (config, error) {
	cfg := defaults()
	count := 0
	seen := make(map[string]bool)
	for c.Next() {
		count++
		if count > 1 {
			return cfg, plugin.ErrOnce
		}
		if len(c.RemainingArgs()) != 0 {
			return cfg, c.ArgErr()
		}
		for c.NextBlock() {
			key, args := c.Val(), c.RemainingArgs()
			if seen[key] {
				return cfg, c.Errf("duplicate %s", key)
			}
			seen[key] = true
			var err error
			switch key {
			case "ttl", "answer_ttl", "peer_timeout":
				if len(args) != 1 {
					return cfg, c.ArgErr()
				}
				d, e := time.ParseDuration(args[0])
				if e != nil {
					if seconds, e2 := strconv.ParseUint(args[0], 10, 32); e2 == nil {
						d, e = time.Duration(seconds)*time.Second, nil
					}
				}
				limit := 7 * 24 * time.Hour
				minimum := time.Second
				if key == "peer_timeout" {
					minimum, limit = time.Millisecond, 2*time.Second
				}
				if e != nil || d < minimum || d > limit {
					return cfg, c.Errf("%s must be between %s and %s", key, minimum, limit)
				}
				switch key {
				case "ttl":
					cfg.retention = d
				case "answer_ttl":
					cfg.answerTTL = d
				case "peer_timeout":
					cfg.peerTimeout = d
				}
			case "capacity", "max_names":
				if len(args) != 1 {
					return cfg, c.ArgErr()
				}
				n, e := strconv.Atoi(args[0])
				limit := 1000000
				if key == "max_names" {
					limit = 128
				}
				if e != nil || n < 1 || n > limit {
					return cfg, c.Errf("%s must be between 1 and %d", key, limit)
				}
				if key == "capacity" {
					cfg.capacity = n
				} else {
					cfg.maxNames = n
				}
			case "peer_listen", "remote":
				if len(args) != 1 {
					return cfg, c.ArgErr()
				}
				if _, err = literalAddress(args[0], true); err != nil {
					return cfg, c.Errf("%s: %v", key, err)
				}
				if key == "peer_listen" {
					cfg.peerListen = args[0]
				} else {
					cfg.remote = args[0]
				}
			case "peers":
				if len(args) == 0 || len(args) > maxPeers {
					return cfg, c.Errf("peers requires 1-%d literal IP:port addresses", maxPeers)
				}
				for _, arg := range args {
					a, e := literalAddress(arg, false)
					if e != nil {
						return cfg, c.Errf("peers: %v", e)
					}
					cfg.peers = append(cfg.peers, a)
				}
			case "discover":
				if len(args) != 3 {
					return cfg, c.Err("discover requires NAME PORT RESOLVER_IP:PORT")
				}
				name, ok := canonicalName(args[0])
				port, e := strconv.ParseUint(args[1], 10, 16)
				resolver, e2 := literalAddress(args[2], false)
				if !ok || name == "." || e != nil || port == 0 || e2 != nil {
					return cfg, c.Err("invalid discover name, port or resolver address")
				}
				cfg.discoverName, cfg.discoverPort, cfg.discoverResolver = name, uint16(port), resolver
			default:
				return cfg, c.Errf("unknown property %q", key)
			}
		}
	}
	if cfg.answerTTL > cfg.retention {
		cfg.answerTTL = cfg.retention
	}
	return cfg, nil
}

func literalAddress(s string, allowZero bool) (string, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil || a.Addr().Zone() != "" || (!allowZero && (a.Port() == 0 || a.Addr().IsUnspecified())) {
		return "", fmt.Errorf("expected a literal IP address and port, got %q", s)
	}
	return a.String(), nil
}
