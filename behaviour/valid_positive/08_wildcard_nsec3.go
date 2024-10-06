package valid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// VP 8

type NSEC3RecordForWildcard struct{}

func (r *NSEC3RecordForWildcard) Setup(ns *naughty.Nameserver) []*naughty.Zone {

	name := dns.Fqdn(fmt.Sprintf("wildcard-with-nsec3.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)

	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DenyExistence = naughty.DefaultDenyExistenceNSEC3

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	// We'll add this record in, that'll be the record before test.
	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("expected-nsec-record.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.54").To4(),
	}
	zone.AddRecord(a)

	a = &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("*.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}
