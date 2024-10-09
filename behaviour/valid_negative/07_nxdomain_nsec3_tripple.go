package valid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

// VN 7

type TripleNXDomainNsec3Response struct{}

func (r *TripleNXDomainNsec3Response) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("three-nsec3-nxdomain.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)
	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	callbacks.DenyExistence = naughty.DefaultDenyExistenceNSEC3

	records := pickRecordsCeThenWcThenNcn(name)
	for _, rr := range records {
		zone.AddRecord(rr)
	}

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}
