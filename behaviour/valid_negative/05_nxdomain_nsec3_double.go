package valid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

// VN 5 & 6

type DoubleCeAndNcnThenWcNXDomainNsec3Response struct{}
type DoubleCeThenNcnAndWcNXDomainNsec3Response struct{}

//type DoubleCeAndWcThenNcnNXDomainNsec3Response struct{}

func (r *DoubleCeAndNcnThenWcNXDomainNsec3Response) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("two-a-nsec3-nxdomain.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)
	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	callbacks.DenyExistence = naughty.DefaultDenyExistenceNSEC3

	records := pickRecordsCeAndNcnThenWc(name)
	for _, rr := range records {
		zone.AddRecord(rr)
	}

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}

func (r *DoubleCeThenNcnAndWcNXDomainNsec3Response) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("two-b-nsec3-nxdomain.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)
	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	callbacks.DenyExistence = naughty.DefaultDenyExistenceNSEC3

	records := pickRecordsCeThenNcnAndWc(name)
	for _, rr := range records {
		zone.AddRecord(rr)
	}

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}

//func (r *DoubleCeAndWcThenNcnNXDomainNsec3Response) Setup(ns *naughty.Nameserver) []*naughty.Zone {
//	name := dns.Fqdn(fmt.Sprintf("two-cc-nsec3-nxdomain.%s", ns.BaseZoneName))
//
//	signer := naughty.NewSignerAutogenSingleDefault(name)
//	callbacks := naughty.NewStandardCallbacks(signer)
//	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
//
//	callbacks.DenyExistence = naughty.DefaultDenyExistenceNSEC3
//
//	records := pickRecordsCeAndWcThenNcn(name)
//	for _, rr := range records {
//		zone.AddRecord(rr)
//	}
//
//	naughty.Info(fmt.Sprintf(logging.LogFmtValid, fmt.Sprintf("test.%s", name)))
//
//	return []*naughty.Zone{zone}
//}
