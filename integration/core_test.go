package integration

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/coremain"
	"github.com/coredns/coredns/plugin"
	_ "github.com/houyuwushang/coredns-rlc/internal/build"
	"github.com/miekg/dns"
)

type input string

func (i input) Body() []byte     { return []byte(i) }
func (input) Path() string       { return "Corefile" }
func (input) ServerType() string { return "dns" }

func start(t *testing.T, corefile string) *caddy.Instance {
	t.Helper()
	caddy.Quiet = true
	dnsserver.Quiet = true
	i, err := caddy.Start(input(corefile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, i) })
	return i
}

func stop(t *testing.T, i *caddy.Instance) {
	t.Helper()
	for _, err := range i.ShutdownCallbacks() {
		t.Error(err)
	}
	if err := i.Stop(); err != nil {
		t.Error(err)
	}
}

func address(i *caddy.Instance, network string) string {
	if network == "tcp" {
		return i.Servers()[0].Addr().String()
	}
	return i.Servers()[0].LocalAddr().String()
}

func exchange(t *testing.T, i *caddy.Instance, network, name string, typ uint16, do bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, typ)
	if do {
		m.SetEdns0(1232, true)
	}
	c := dns.Client{Net: network, Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, address(i, network))
	if err != nil {
		t.Fatal(err)
	}
	if r.Id != m.Id || !r.Response || len(r.Question) != 1 || r.Question[0] != m.Question[0] {
		t.Fatal("invalid wire response", r)
	}
	return r
}

func ptrNames(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			out = append(out, p.Ptr)
		}
	}
	sort.Strings(out)
	return out
}

func zones(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"forward.zone": `$ORIGIN example.org.
@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60
@ 60 IN NS ns.example.org.
ns 60 IN A 192.0.2.53
www 1 IN CNAME edge.example.org.
edge 1 IN A 192.0.2.7
edge 1 IN AAAA 2001:db8::7
`,
		"reverse.zone": `$ORIGIN in-addr.arpa.
@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60
@ 60 IN NS ns.example.org.
7.2.0.192 60 IN PTR authoritative.example.org.
`,
		"reverse6.zone": `$ORIGIN ip6.arpa.
@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60
@ 60 IN NS ns.example.org.
`,
	}
	for name, s := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return strings.ReplaceAll(dir, "\\", "/")
}

func upstream(t *testing.T) *caddy.Instance {
	dir := zones(t)
	return start(t, fmt.Sprintf(`.:0 {
 file %s/forward.zone example.org
 file %s/reverse.zone in-addr.arpa
 file %s/reverse6.zone ip6.arpa
}`, dir, dir, dir))
}

func TestCoreDNSForwardCachePTRAndDNSSEC(t *testing.T) {
	auth := upstream(t)
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			i := start(t, fmt.Sprintf(`.:0 {
 rlc {
  ttl 1h
 }
 cache 60
 forward . %s
}`, address(auth, network)))
			v4, _ := dns.ReverseAddr("192.0.2.7")
			v6, _ := dns.ReverseAddr("2001:db8::7")
			if got := ptrNames(exchange(t, i, network, v4, dns.TypePTR, false)); !reflect.DeepEqual(got, []string{"authoritative.example.org."}) {
				t.Fatal(got)
			}
			if got := exchange(t, i, network, v6, dns.TypePTR, false); got.Rcode != dns.RcodeNameError {
				t.Fatal("expected negative PTR before observation", got)
			}
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
				r := exchange(t, i, network, "www.example.org.", typ, false)
				if r.Rcode != 0 || len(r.Answer) != 2 {
					t.Fatal(r)
				}
			}
			for _, name := range []string{v4, v6} {
				r := exchange(t, i, network, name, dns.TypePTR, false)
				if got := ptrNames(r); !reflect.DeepEqual(got, []string{"edge.example.org.", "www.example.org."}) {
					t.Fatal("cache hid observed names", r)
				}
				if r.Authoritative || r.AuthenticatedData || r.Rcode != 0 {
					t.Fatal("incorrect synthetic response flags", r)
				}
				for _, rr := range r.Answer {
					if rr.Header().Ttl > 5 {
						t.Fatal("unbounded answer TTL")
					}
				}
			}
			if got := ptrNames(exchange(t, i, network, v4, dns.TypePTR, true)); !reflect.DeepEqual(got, []string{"authoritative.example.org."}) {
				t.Fatal("DO request was synthesized", got)
			}
			if got := exchange(t, i, network, v6, dns.TypePTR, true); got.Rcode != dns.RcodeNameError {
				t.Fatal("DO denial replaced", got)
			}
		})
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func TestCoreDNSReloadAndFailedReload(t *testing.T) {
	auth := upstream(t)
	peer, remote := freePort(t), freePort(t)
	config := fmt.Sprintf(`.:0 {
 rlc {
  peer_listen %s
  remote %s
 }
 forward . %s
}`, peer, remote, address(auth, "udp"))
	i, err := caddy.Start(input(config))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { stop(t, i) }()
	for range 2 {
		exchange(t, i, "udp", "www.example.org.", dns.TypeA, false)
		client := dns.Client{Net: "tcp", Timeout: time.Second}
		q := new(dns.Msg)
		q.SetQuestion("7.2.0.192.in-addr.arpa.", dns.TypePTR)
		r, _, err := client.Exchange(q, peer)
		if err != nil || len(ptrNames(r)) != 2 {
			t.Fatalf("peer not serving: %v %v", r, err)
		}
		next, err := i.Restart(input(config))
		if err != nil {
			if runtime.GOOS != "windows" || !strings.Contains(err.Error(), "getting old listener file") {
				t.Fatal(err)
			}
			// Caddy cannot duplicate a Windows socket with pending I/O. Its
			// failed-reload callback must nevertheless restore our listeners.
			r, _, e := client.Exchange(q, peer)
			if e != nil || len(ptrNames(r)) != 2 {
				t.Fatalf("failed reload did not restore old listener: %v %v", r, e)
			}
			t.Log("Caddy's Windows socket duplication failed; plugin rollback verified. Successful reload is exercised on Unix.")
			break
		}
		i = next
	}
	// A rejected new Corefile must reopen the old listeners and preserve its data.
	exchange(t, i, "udp", "www.example.org.", dns.TypeA, false)
	if _, err := i.Restart(input(".:0 {\n rlc {\n unknown value\n }\n}")); err == nil {
		t.Fatal("invalid reload accepted")
	}
	c := dns.Client{Net: "tcp", Timeout: time.Second}
	q := new(dns.Msg)
	q.SetQuestion("7.2.0.192.in-addr.arpa.", dns.TypePTR)
	r, _, err := c.Exchange(q, peer)
	if err != nil || len(ptrNames(r)) != 2 {
		t.Fatalf("old peer listener not restored: %v %v", r, err)
	}
}

func init() {
	plugin.Register("rlc_test_fail_start", func(c *caddy.Controller) error {
		c.OnStartup(func() error { return fmt.Errorf("deliberate late startup failure") })
		return nil
	})
	dnsserver.Directives = append(dnsserver.Directives, "rlc_test_fail_start")
}

func TestLateFailedReloadReleasesNewPorts(t *testing.T) {
	auth := upstream(t)
	config := func(peer, remote, extra string) string {
		return fmt.Sprintf(`.:0 {
 rlc {
  peer_listen %s
  remote %s
 }
 forward . %s
 %s
}`, peer, remote, address(auth, "udp"), extra)
	}
	oldPeer, oldRemote := freePort(t), freePort(t)
	i := start(t, config(oldPeer, oldRemote, ""))
	exchange(t, i, "udp", "www.example.org.", dns.TypeA, false)
	newPeer, newRemote := freePort(t), freePort(t)
	if _, err := i.Restart(input(config(newPeer, newRemote, "rlc_test_fail_start"))); err == nil || !strings.Contains(err.Error(), "deliberate late startup failure") {
		t.Fatal(err)
	}
	for _, address := range []string{newPeer, newRemote} {
		l, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatalf("failed instance leaked listener %s: %v", address, err)
		}
		l.Close()
	}
	q := new(dns.Msg)
	q.SetQuestion("7.2.0.192.in-addr.arpa.", dns.TypePTR)
	c := dns.Client{Net: "tcp", Timeout: time.Second}
	r, _, err := c.Exchange(q, oldPeer)
	if err != nil || len(ptrNames(r)) != 2 {
		t.Fatalf("old cache/listener was not restored: %v %v", r, err)
	}
}
