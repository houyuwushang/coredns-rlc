# rlc

## Name

*rlc* is an external CoreDNS plugin that answers reverse lookups using names
observed in successful forward DNS answers.

## Description

After observing `www.example.org. A 192.0.2.7`, *rlc* can answer a PTR query
for `192.0.2.7` with `www.example.org.`. It supports IPv4, IPv6 and CNAME chains,
including the original queried name. This can help annotate logs when a CDN's
ordinary reverse DNS name is absent or unhelpful.

These are **observed names**, not authoritative reverse DNS or proof of which
virtual host a connection used. A shared IP may have several names. Answers
contain a bounded, alphabetically sorted set; the first name has no special
meaning. Observations are shared by clients of the same server block. Separate
server blocks have separate caches; only explicitly configured peers and dnstap
inputs share data between them.

On a hit, *rlc* answers before downstream plugins, including an authoritative
PTR provider. On a miss, it passes the query down the normal chain. Requests
with DNSSEC DO, TSIG, a non-IN class or a non-QUERY opcode pass through unchanged.
Synthetic answers have neither AA nor AD set. DNSSEC-aware clients should use
the normal reverse DNS result, not this enrichment view.

Only complete, successful A/AAAA answers on the requested CNAME chain are
learned. Unrelated answer records and the additional section are ignored.
Retention is measured from the observation, independently of the source DNS
TTL, including zero TTL: this is intentionally a short history of observations.
PTR queries do not renew it. A later forward observation can renew it.
Data is held in memory and cleared on a successful restart/reload.

## Installation

Requires Go 1.26 or later. The integration tests use CoreDNS v1.15.0.

Build the included small CoreDNS distribution:

```sh
git clone https://github.com/houyuwushang/coredns-rlc.git
cd coredns-rlc
go build ./cmd/coredns-rlc
./coredns-rlc -plugins
./coredns-rlc -conf Corefile
```

It includes *rlc*, *cache*, *forward*, *file*, *hosts*, *dnstap*, *errors*, *log*,
*prometheus*, *health*, *ready* and *reload*. For other plugins, including
*kubernetes*, build a full CoreDNS distribution instead:

1. Check out the desired CoreDNS release.
2. Add `rlc:github.com/houyuwushang/coredns-rlc` **immediately before**
   `cache:cache` in `plugin.cfg`.
3. Run `go get github.com/houyuwushang/coredns-rlc`, `go generate`, `go mod tidy`,
   and `go build`.

Plugin execution order comes from `plugin.cfg`, not the Corefile. Keeping *rlc*
before *cache* lets it observe cached forward answers and answer newly learned
PTRs even when the regular cache holds an older negative PTR. Synthetic answers
are produced before the regular cache and are not stored in it.

## Syntax

```corefile
rlc {
    ttl DURATION
    answer_ttl DURATION
    capacity PAIRS
    max_names NAMES
    peer_listen IP:PORT
    peers IP:PORT...
    peer_timeout DURATION
    discover NAME PORT RESOLVER_IP:PORT
    remote IP:PORT
}
```

All properties are optional. The plugin can appear once per server block.

| Property | Default | Meaning |
| --- | --- | --- |
| `ttl` | `1h` | Observation retention, from 1 second to 7 days. |
| `answer_ttl` | `5s` | Maximum PTR TTL; also bounded by remaining retention. |
| `capacity` | `10000` | Maximum IP/name pairs, from 1 to 1,000,000. |
| `max_names` | `16` | Maximum names per IP and per answer, from 1 to 128. |
| `peer_listen` | disabled | Dedicated TCP DNS listener serving local observations only. |
| `peers` | none | Up to 32 literal peer IP:port addresses. IPv6 uses `[IP]:PORT`. |
| `peer_timeout` | `200ms` | Total peer-query budget, from 1ms to 2s. |
| `discover` | disabled | Resolve an absolute DNS name through the specified resolver to find peer IPs. |
| `remote` | disabled | TCP listener accepting bidirectional dnstap Frame Streams. |

Durations accept Go units, such as `30m`, or integer seconds. Answer TTL is
capped at retention; records with less than a second remaining have TTL 0.
Capacity counts pairs rather than just IPs, bounding memory even for shared IPs.
At capacity, the least recently ingested/refreshed pair is evicted. Per-IP limits
evict the oldest observation. Lookups do not affect either limit or expiry.

Peer and dnstap listeners require explicit literal bind addresses. Use loopback
for local collectors, or private addresses with network access restricted to
trusted collectors and peers. These optional protocols do not authenticate or
encrypt traffic. A dnstap sender can introduce names; a peer can influence
enrichment answers. Do not expose these endpoints to untrusted networks.

## Examples

### Single instance

```corefile
.:1053 {
    rlc {
        ttl 30m
        capacity 50000
    }
    cache 30
    forward . /etc/resolv.conf
}
```

Use an explicit upstream address instead of `/etc/resolv.conf` if that file
points back to this server.

### Two instances

On a node with address `192.0.2.10`:

```corefile
.:1053 {
    rlc {
        peer_listen 192.0.2.10:8054
        peers 192.0.2.11:8054
    }
    cache 30
    forward . /etc/resolv.conf
}
```

Configure the other node with the addresses exchanged. Peers are queried over
TCP on both local hits and misses, and results are combined. The peer listener
answers only from its own cache: it never forwards or queries other peers.
Received names are not cached again, preventing reads from extending retention.
Unavailable peers are ignored after the query budget. At most 64 outbound peer
queries run concurrently per plugin instance; busy peers may therefore be
omitted. Results are best effort, not a strongly consistent distributed history.

### Kubernetes peer discovery

Create a **headless Service** selecting the CoreDNS pods and exposing TCP 8054.
With a full CoreDNS build containing *kubernetes*, add these properties to *rlc*:

```text
peer_listen 0.0.0.0:8054
discover rlc-peers.kube-system.svc.cluster.local. 8054 10.96.0.10:53
```

Replace the service name and resolver IP with the cluster's actual values.
The resolver must serve the headless Service's A/AAAA records. Discovery refreshes
every 30 seconds, starts asynchronously, and needs no Kubernetes API credentials.
A failed refresh clears discovered peers; static peers are retained. Up to 32
unique peers are used. Self-discovery is safe because the peer listener is local
only. Restrict TCP 8054 access with the cluster's network policy.

### Import observations from dnstap

On the enrichment server:

```corefile
.:1053 {
    rlc {
        remote 127.0.0.1:8053
    }
    forward . /etc/resolv.conf
}
```

On a CoreDNS resolver in the same network namespace, enable response messages:

```text
dnstap tcp://127.0.0.1:8053 full
```

Only dnstap response event types and `response_message` are accepted. Query-only
events cannot seed the cache. Response timestamps preserve the original age;
expired events are discarded and future timestamps are capped at receipt time.
If a response timestamp is absent, receipt time is used. PTR events are ignored
to avoid feeding synthesized answers back into the observation history.

The listener accepts at most 16 connections and 128 KiB frames, with bounded
handshake and idle timeouts. A sender must reconnect after an idle disconnect.

## Readiness and reload

With CoreDNS's *ready* plugin enabled, *rlc* is ready once its configured local
listeners start. Peer availability is not required for local answers. Binding
errors fail startup and close partially opened listeners. A failed reload
restores the previous plugin instance and its observations. Successful reloads
start with an empty cache.

CoreDNS/Caddy's Windows socket-duplication limitation can reject a DNS listener
reload. The Windows integration test verifies recovery from that failure; Linux
and macOS tests exercise successful reloads as well.

## Validation

```sh
go test -race -count=1 ./...
go vet ./...
go test -run '^$' -fuzz FuzzReverseAddress -fuzztime 15s
go test -run '^$' -fuzz FuzzReverseMalformed -fuzztime 15s
```

The suite includes standard IPv4/IPv6 reverse names, escaped DNS names, CNAME
learning, memory/retention bounds, concurrent access, real TCP peer queries,
headless-service DNS discovery, real dnstap Frame Streams, malformed input, and
real CoreDNS UDP/TCP forwarding, caching, DNSSEC pass-through and reloads. CI
also builds the plugin through a full CoreDNS `plugin.cfg` integration.

## Origin and maintenance

This independent implementation continues the use case proposed by
[Carsten Zeumer (@czeumer) in CoreDNS #6459](https://github.com/coredns/coredns/pull/6459),
following the discussion's external-plugin direction. Thanks to the original
author and reviewers for identifying the use case and its semantic limitations.

It replaces the proposed groupcache integration with bounded, local-only TCP
DNS peer lookups and DNS-based discovery. It is not configuration- or protocol-
compatible with the unmerged prototype's `groupcache` option. `remote` takes an
explicit bind address, and PTR imports are intentionally unsupported.

Maintained by [houyuwushang](https://github.com/houyuwushang). This is an
independent plugin, not an official CoreDNS component. Report issues in this
repository. Contributions should include tests and a `Signed-off-by` trailer.
