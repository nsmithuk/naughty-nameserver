package invalid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// IN 6

// Warning: This test requires a zone hosted elsewhere, to delegate to, for it to make sense.
// It's setup to work with either naughty.qazz.uk or naughty-nameserver.com only.
// If you want to host this yourself, you'll need a zone setting up for `fmt.Sprintf("test.%s", name)`
// And you'll need to set a NS record pointing to that zone.

type MissingDSRecords struct{}

func (r *MissingDSRecords) Setup(ns *naughty.Nameserver) []*naughty.Zone {

	name := dns.Fqdn(fmt.Sprintf("missing-ds-records.%s", ns.BaseZoneName))
	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	// We return no DS records.
	callbacks.DelegatedSingers = func() []*dns.DS {
		return []*dns.DS{}
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtInvalid, a.Header().Name))

	//---

	return []*naughty.Zone{zone}
}
