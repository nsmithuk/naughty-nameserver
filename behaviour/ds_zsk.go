package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"log"
	"net"
)

type ZskDS struct{}

func (t *ZskDS) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("zsk-ds.%s", ns.BaseZoneName))

	signer, err := naughty.NewSignerAutogenPair(name, dns.ECDSAP256SHA256, 256, dns.ECDSAP256SHA256, 256)
	if err != nil {
		return err
	}

	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DelegatedSingers = func() []*dns.DS {
		// We return the ZSK (wrong) DS.
		return signer.Zsk.DelegatedSingers()
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
