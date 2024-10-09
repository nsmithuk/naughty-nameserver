package invalid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

// IN 5

type InvalidNsec3Flag struct{}

func (r *InvalidNsec3Flag) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("nsec3-invalid-flag.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.DenyExistence = func(msg *dns.Msg, z *naughty.Zone, wildcardsUsed naughty.SynthesisedResults) (*dns.Msg, error) {
		var err error
		msg, err = naughty.DefaultDenyExistenceNSEC3(msg, z, wildcardsUsed)

		for _, rr := range msg.Ns {
			if nsec3, ok := rr.(*dns.NSEC3); ok {
				// We set this to an invalid value. i.e. not 0 or 1.
				nsec3.Flags = 2
			}
		}

		return msg, err
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	// No record, thus a NXDOMAIN.

	naughty.Info(fmt.Sprintf(logging.LogFmtInvalid, fmt.Sprintf("test.%s", name)))

	return []*naughty.Zone{zone}
}
