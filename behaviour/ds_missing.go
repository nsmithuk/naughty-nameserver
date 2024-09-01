package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

type MissingDS struct{}

func (t *MissingDS) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("missing-ds.%s", ns.BaseZoneName))

	callbacks := naughty.NewStandardCallbacks(naughty.NewSignerAutogenSingleDefault(name))

	callbacks.DelegatedSingers = func() []*dns.DS {
		// Means no DS record will be set
		return []*dns.DS{}
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Log.Infof(logFmtInvalid, a.Header().Name)

	return nil

}
