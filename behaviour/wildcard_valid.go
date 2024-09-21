package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// WildcardValid has a wildcard record that will catch `test.`, rather than an explicit record.
type WildcardValid struct{}

func (t *WildcardValid) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("wildcard.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)

	zone := naughty.NewZone(name, ns.NSRecords, naughty.NewStandardCallbacks(signer))
	if err := ns.RegisterZone(zone); err != nil {
		naughty.Warn(fmt.Sprintf("Failed to register zone '%s': %s", name, err.Error()))
		return err
	}

	// We'll add this record in, that'll be the record before test.
	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("expected-nsec-record.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.54").To4(),
	}
	zone.AddRecord(a)

	a = &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("*.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logFmtValid, fmt.Sprintf("test.wildcard.%s", ns.BaseZoneName)))

	return nil
}
