package valid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"maps"
	"net"
)

// VP 13

// Warning: This test requires a zone hosted elsewhere, to delegate to, for it to make sense.
// It's setup to work with either naughty.qazz.uk or naughty-nameserver.com only.
// If you want to host this yourself, you'll need a zone setting up for `fmt.Sprintf("test.%s", name)`
// And you'll need to set a NS record pointing to that zone.

type OptoutDSNsec3RecordDeligation struct{}

func (r *OptoutDSNsec3RecordDeligation) Setup(ns *naughty.Nameserver) []*naughty.Zone {

	name := dns.Fqdn(fmt.Sprintf("deligation-optout-nsec3.%s", ns.BaseZoneName))
	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DenyExistence = func(msg *dns.Msg, z *naughty.Zone, wildcardsUsed naughty.SynthesisedResults) (*dns.Msg, error) {

		// After setting the onward NS record, we remove `test.` from the store.
		// This results in the NSEC3 records being generated such that the record does not exist.
		// The `a.` and `b.` records result in a setup where-by `test.` is *covered* by the NSEC3
		// records. We then set the opt-out flag, thus the end result should be Insecure (but valid).

		store := maps.Clone(z.Records)

		delete(store, fmt.Sprintf("test.%s", name))

		qname := dns.Fqdn(msg.Question[0].Name)

		records := make([]dns.RR, 0, 3)
		records = append(records, store.GetNSEC3ClosestEncloserRecord(qname, z.Name))
		records = append(records, store.GetNSEC3Record(qname, z.Name))
		records = append(records, store.GetNSEC3Record(naughty.WildcardName(qname), z.Name))

		records = dns.Dedup(records, nil)

		// We set the opt-out flat to 1.
		for _, rr := range records {
			if nsec3, ok := rr.(*dns.NSEC3); ok {
				nsec3.Flags = 1
			}
		}

		msg.Ns = append(msg.Ns, records...)

		return msg, nil
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	nameserver := &dns.NS{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeNS),
		Ns:  "ns1.digitalocean.com.",
	}
	zone.AddRecord(nameserver)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("a.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.54").To4(),
	}
	zone.AddRecord(a)

	a = &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("b.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, nameserver.Header().Name))

	//---

	return []*naughty.Zone{zone}
}
