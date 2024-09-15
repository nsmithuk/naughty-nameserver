package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
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
	if err := ns.RegisterZone(zone); err != nil {
		naughty.Warn(fmt.Sprintf("Failed to register zone '%s': %s", name, err.Error()))
		return err
	}

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logFmtValid, a.Header().Name))

	return nil

}
