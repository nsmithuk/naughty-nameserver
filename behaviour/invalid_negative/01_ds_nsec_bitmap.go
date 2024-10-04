package invalid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"slices"
)

// IN 1

// Warning: This test requires a zone hosted elsewhere, to delegate to, for it to make sense.
// It's setup to work with either naughty.qazz.uk or naughty-nameserver.com only.
// If you want to host this yourself, you'll need a zone setting up for `fmt.Sprintf("test.%s", name)`
// And you'll need to set a NS record pointing to that zone.

type InvalidDSNsecRecordDeligation struct{}

func (r *InvalidDSNsecRecordDeligation) Setup(ns *naughty.Nameserver) []*naughty.Zone {

	name := dns.Fqdn(fmt.Sprintf("invalid-deligation-nsec-bitmap.%s", ns.BaseZoneName))
	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DenyExistence = func(msg *dns.Msg, z *naughty.Zone, wildcardsUsed naughty.SynthesisedResults) (*dns.Msg, error) {

		// We add DS to the TypeBitMap, implying the record should exist.

		var err error
		msg, err = naughty.DefaultDenyExistenceNSEC(msg, z, wildcardsUsed)

		for _, rr := range msg.Ns {
			if nsec, ok := rr.(*dns.NSEC); ok {
				nsec.TypeBitMap = append(nsec.TypeBitMap, dns.TypeDS)
				slices.Sort(nsec.TypeBitMap)
			}
		}

		return msg, err
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	nameserver := &dns.NS{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeNS),
		Ns:  "ns1.digitalocean.com.",
	}
	zone.AddRecord(nameserver)

	naughty.Info(fmt.Sprintf(logging.LogFmtInvalid, nameserver.Header().Name))

	//---

	return []*naughty.Zone{zone}
}