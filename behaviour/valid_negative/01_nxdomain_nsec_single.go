package valid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// VN 1

type SingleNXDomainNsecResponse struct{}

func (r *SingleNXDomainNsecResponse) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("one-nsec-nxdomain.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)
	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	// A single record at the "end" of the zone will mean both * and `test` are covered by a single NSEC record.
	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("zzz.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}
