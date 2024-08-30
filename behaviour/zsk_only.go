package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"naughty-nameserver/naughty"
	"net"
)

/*
ZskOnly is a zone with no KSK, only a ZSK.

We will sign both the DNSKEY RRs and the normal RRs with this key.

The DS record for the zone will be generated from the ZSK.

THis setup is not valid; the DS record must be generated from a key with a flag for 257.
i.e. a KSK/CSK.
*/
type ZskOnly struct{}

func (t *ZskOnly) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("zsk-only.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleSimple(name)

	// Set this to be a Zone Signing Key.
	signer.SetDnsKeyFlag(naughty.DnskeyFlagZsk)

	zone := naughty.NewZone(name, ns.NSRecords, signer, new(naughty.DefaultMutator))
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	log.Printf("Invalid record added: %s\n", a.Header().Name)

	return nil
}
