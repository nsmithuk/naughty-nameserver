package valid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
	"slices"
)

// VP 12

type MultipleDsRecords struct{}

func (r *MultipleDsRecords) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("multiple-ds.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DelegatedSingers = func() []*dns.DS {
		// We return the real records, but a couple of other random ones.
		return slices.Concat(
			naughty.NewSignerAutogenSingleDefault(name).DelegatedSingers(),
			signer.DelegatedSingers(),
			naughty.NewSignerAutogenSingleDefault(name).DelegatedSingers(),
		)
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, a.Header().Name))

	return []*naughty.Zone{zone}
}
