package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"naughty-nameserver/naughty"
	"net"
	"slices"
)

type MultipleDS struct{}

func (t *MultipleDS) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("multiple-ds.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DelegatedSingers = func() []*dns.DS {
		// Means no DS record will be set
		return slices.Concat(
			naughty.NewSignerAutogenSingleDefault(name).DelegatedSingers(),
			signer.DelegatedSingers(),
			naughty.NewSignerAutogenSingleDefault(name).DelegatedSingers(),
		)
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	log.Printf("Valid record added: %s\n", a.Header().Name)

	return nil

}
