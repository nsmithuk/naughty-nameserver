package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"naughty-nameserver/naughty"
	"net"
)

type IncorrectDS struct{}

func (t *IncorrectDS) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("incorrect-ds.%s", ns.BaseZoneName))

	callbacks := naughty.NewStandardCallbacks(naughty.NewSignerAutogenSingleDefault(name))

	callbacks.DelegatedSingers = func() []*dns.DS {
		// Generates a new key and returns the DS record for that instead.
		return naughty.NewSignerAutogenSingleDefault(name).DelegatedSingers()
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	log.Printf("Invalid record added: %s\n", a.Header().Name)

	return nil

}
