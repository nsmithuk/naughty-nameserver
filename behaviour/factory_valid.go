package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"naughty-nameserver/naughty"
	"net"
)

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

		signer, err := naughty.NewSimpleAlgorithmSigner(name, c.algorithm, c.bits)
		if err != nil {
			return err
		}

		zone := naughty.NewZone(name, ns.NSRecords, signer, new(naughty.DefaultMutator))
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
