package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

type MissmatchDS struct{}

func (t *MissmatchDS) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("missmatch-ds.%s", ns.BaseZoneName))

	signerUsed := naughty.NewSignerAutogenSingleDefault(name)
	signerUnused := naughty.NewSignerAutogenSingleDefault(name)

	callbacks := naughty.NewStandardCallbacks(signerUsed)

	callbacks.Keys = func() []*dns.DNSKEY {
		// We return the key for both
		return append(signerUsed.Keys(), signerUnused.Keys()...)
	}
	callbacks.DelegatedSingers = func() []*dns.DS {
		// We only return the DS record for the unused key.
		return signerUnused.DelegatedSingers()
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logFmtInvalid, a.Header().Name))

	return nil

}
