package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"naughty-nameserver/naughty"
	"net"
)

/*
AllValidAlgorithms covers 6 valid/working use cases, each signed with a CSK.

To use: test.rsa-1024-sha1.<base-domain>
To use: test.rsa-2048-sha256.<base-domain>
To use: test.rsa-4096-sha512.<base-domain>
To use: test.ecdsa-p256-sha256.<base-domain>
To use: test.ecdsa-p384-sha384.<base-domain>
To use: test.ed25519.<base-domain>
*/
type AllValidAlgorithms struct {
}

func (t *AllValidAlgorithms) Setup(ns *naughty.Nameserver) error {

	type combination struct {
		name      string
		algorithm uint8
		bits      int
	}

	combinations := []combination{
		{"rsa-1024-sha1", dns.RSASHA1, 1024},
		{"rsa-2048-sha256", dns.RSASHA256, 2048},
		{"rsa-4096-sha512", dns.RSASHA512, 4096},
		{"ecdsa-p256-sha256", dns.ECDSAP256SHA256, 256},
		{"ecdsa-p384-sha384", dns.ECDSAP384SHA384, 384},
		{"ed25519", dns.ED25519, 256},
	}

	for _, c := range combinations {
		name := fmt.Sprintf("%s.%s", c.name, ns.BaseZoneName)

		signer, err := naughty.NewSignerAutogenSingle(name, c.algorithm, c.bits)
		if err != nil {
			return err
		}

		zone := naughty.NewZone(name, ns.NSRecords, naughty.NewStandardCallbacks(signer))
		ns.BaseZone.DelegateTo(zone)
		ns.Zones[name] = zone

		a := &dns.A{
			Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		}
		zone.AddRecord(a)

		log.Printf("Valid record added: %s\n", a.Header().Name)
	}

	return nil
}
