package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

/*
InvalidRRSigSignature returns an invalid rrsig for the RR.

It does this by signing a response with a different A record IP address, then the
one returned to the user.

To use: test.rrsig-signature-invalid.<base-domain>
*/
type InvalidRRSigSignature struct {
	answer  dns.RR
	valid   net.IP
	invalid net.IP
}

func (t *InvalidRRSigSignature) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("rrsig-signature-invalid.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.Sign = func(msg *dns.Msg) (*dns.Msg, error) {
		t.answer.(*dns.A).A = t.invalid
		signedMsg, err := signer.Sign(msg)
		t.answer.(*dns.A).A = t.valid
		return signedMsg, err
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	//---

	t.valid = net.ParseIP("192.0.2.53").To4()
	t.invalid = net.ParseIP("192.0.2.72").To4()

	//---

	t.answer = &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   t.valid,
	}
	zone.AddRecord(t.answer)

	naughty.Log.Infof(logFmtInvalid, t.answer.Header().Name)

	return nil
}
