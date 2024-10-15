package valid_positive

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// VP 14 - 16

type AlgorithmCombinationsPqc struct{}

func (r *AlgorithmCombinationsPqc) Setup(ns *naughty.Nameserver) []*naughty.Zone {

	type combination struct {
		name      string
		algorithm uint8
	}

	combinations := []combination{
		{"ml-dsa-44", dns.MLDSA44},
		{"ml-dsa-65", dns.MLDSA65},
		{"ml-dsa-87", dns.MLDSA87},
	}

	zones := make([]*naughty.Zone, len(combinations))
	for i, c := range combinations {
		name := fmt.Sprintf("%s.%s", c.name, ns.BaseZoneName)

		signer, err := naughty.NewSignerAutogenSingleMLDSA(name, c.algorithm)
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
