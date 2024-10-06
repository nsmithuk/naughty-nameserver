package invalid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// IP 7

type MissingRRSig struct{}

func (r *MissingRRSig) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("missing-rrsig.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.Sign = func(m *dns.Msg) (*dns.Msg, error) {
		msg, err := signer.Sign(m)

		// We remove the RRSIG for the `test.` domain, thus one RRSIG is missing.
		answers := make([]dns.RR, 0, len(msg.Answer)-1)
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype == dns.TypeRRSIG && rr.Header().Name == fmt.Sprintf("test.%s", name) {
				continue
			}
			answers = append(answers, rr)
		}
		msg.Answer = answers

		return msg, err
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("answer.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	cname := &dns.CNAME{
		Hdr:    naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeCNAME),
		Target: a.Header().Name,
	}
	zone.AddRecord(cname)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, cname.Header().Name))

	return []*naughty.Zone{zone}
}
