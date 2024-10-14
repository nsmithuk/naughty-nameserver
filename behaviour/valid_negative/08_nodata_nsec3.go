package valid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

// VN 8

type NODataNsec3Response struct{}

func (r *NODataNsec3Response) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("nsec3-nodata.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DenyExistence = naughty.DefaultDenyExistenceNSEC3

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	// We'll set an MX record so a query for an A record will give NODATA.
	mx := &dns.MX{
		Hdr:        naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeMX),
		Preference: 10,
		Mx:         "mail.example.com.",
	}
	zone.AddRecord(mx)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, mx.Header().Name))

	return []*naughty.Zone{zone}
}
