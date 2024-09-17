package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
)

// CnameChain Has a chain of wildcarded CNAME. As per https://datatracker.ietf.org/doc/html/rfc7129#section-5.4
type CnameChain struct{}

func (t *CnameChain) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("cname-chain.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)

	zone := naughty.NewZone(name, ns.NSRecords, naughty.NewStandardCallbacks(signer))
	if err := ns.RegisterZone(zone); err != nil {
		naughty.Warn(fmt.Sprintf("Failed to register zone '%s': %s", name, err.Error()))
		return err
	}

	cname := &dns.CNAME{
		Hdr:    naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeCNAME),
		Target: "w.a",
	}
	zone.AddRecord(cname)

	cname = &dns.CNAME{
		Hdr:    naughty.NewHeader(fmt.Sprintf("*.a.%s", name), dns.TypeCNAME),
		Target: "w.b",
	}
	zone.AddRecord(cname)

	cname = &dns.CNAME{
		Hdr:    naughty.NewHeader(fmt.Sprintf("*.b.%s", name), dns.TypeCNAME),
		Target: "w.c",
	}
	zone.AddRecord(cname)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("*.c.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logFmtValid, fmt.Sprintf("test.%s", name)))

	return nil
}
