// coredns-rlc is a small CoreDNS distribution for log-enrichment deployments.
package main

import (
	"github.com/coredns/coredns/coremain"
	_ "github.com/houyuwushang/coredns-rlc/internal/build"
)

func main() { coremain.Run() }
