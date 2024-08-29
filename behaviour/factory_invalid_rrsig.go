package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"naughty-nameserver/naughty"
	"net"
)

type InvalidRRSig struct {
	answer  dns.RR
	valid   net.IP
	invalid net.IP
}

func (t *InvalidRRSig) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("rrsig-signature-invalid.%s", ns.BaseZoneName))

	zone := naughty.NewZone(name, ns.NSRecords, naughty.NewSimpleSigner(name), t)
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

	return nil
}

func (t *InvalidRRSig) PreSigning(msg *dns.Msg) *dns.Msg {
	// Change the answer to something else.
	t.answer.(*dns.A).A = t.invalid
	return msg
}

func (t *InvalidRRSig) PostSigning(msg *dns.Msg) *dns.Msg {
	// Revert back to the original.
	t.answer.(*dns.A).A = t.valid
	return msg
}
