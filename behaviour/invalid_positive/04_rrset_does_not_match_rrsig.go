package invalid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// IP 4

type RRSetDoesNotMatchRRSig struct{}

func (r *RRSetDoesNotMatchRRSig) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("invalid-signature-message.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	callbacks.Sign = func(m *dns.Msg) (*dns.Msg, error) {
		msg, err := signer.Sign(m)
		for i, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				aClone := dns.Copy(a).(*dns.A)
				aClone.A = net.ParseIP("192.0.2.54").To4() // We change the IP
				m.Answer[i] = aClone
			}
		}
		return msg, err
	}

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, a.Header().Name))

	return []*naughty.Zone{zone}
}
