package valid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// VP 10

type KeyFlag257 struct{}

func (r *KeyFlag257) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("key-flag-256.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)

	signer.Key().Flags = uint16(257)

	callbacks := naughty.NewStandardCallbacks(signer)

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, a.Header().Name))

	return []*naughty.Zone{zone}
}
