package invalid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// IP 3

type DsKeyMissmatch struct{}

func (r *DsKeyMissmatch) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("ds-key-missmatch.%s", ns.BaseZoneName))

	signer, err := naughty.NewSignerAutogenPair(name, dns.ECDSAP256SHA256, 256, dns.ECDSAP256SHA256, 256)
	if err != nil {
		panic(err)
	}

	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DelegatedSingers = func() []*dns.DS {
		// We only return the DS records for the ZSK.
		return signer.Zsk.DelegatedSingers()
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtInvalid, a.Header().Name))

	return []*naughty.Zone{zone}
}
