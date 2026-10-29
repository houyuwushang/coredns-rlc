// Package build selects the plugins included in the example server.
package build

import (
	"slices"

	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/dnstap"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/file"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/hosts"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metrics"
	_ "github.com/coredns/coredns/plugin/ready"
	_ "github.com/coredns/coredns/plugin/reload"
	_ "github.com/houyuwushang/coredns-rlc"
)

func init() {
	i := slices.Index(dnsserver.Directives, "cache")
	dnsserver.Directives = slices.Insert(dnsserver.Directives, i, "rlc")
}
