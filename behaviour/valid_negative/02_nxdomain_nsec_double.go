package valid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// VN 2

type DoubleNXDomainNsecResponse struct{}

func (r *DoubleNXDomainNsecResponse) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("two-nsec-nxdomain.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)
	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	// A record after *. but before `test` will mean two NSEC records are needed.
	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("aaa.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}
