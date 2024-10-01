package valid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// VP 1 to 6

type AlgorithmCombinations struct{}

func (r *AlgorithmCombinations) Setup(ns *naughty.Nameserver) []*naughty.Zone {

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

	zones := make([]*naughty.Zone, len(combinations))
	for i, c := range combinations {
		name := fmt.Sprintf("%s.%s", c.name, ns.BaseZoneName)

		signer, err := naughty.NewSignerAutogenSingle(name, c.algorithm, c.bits)
		if err != nil {
			panic(err)
		}

		zones[i] = naughty.NewZone(name, ns.NSRecords, naughty.NewStandardCallbacks(signer))
		a := &dns.A{
			Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		}
		zones[i].AddRecord(a)

		naughty.Info(fmt.Sprintf(logging.LogFmtValid, a.Header().Name))
	}

	return zones
}
