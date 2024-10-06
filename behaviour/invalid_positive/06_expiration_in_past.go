package invalid_positive

import (
	"crypto"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour/logging"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
	"time"
)

// IP 6

type ExpirationInPast struct{}

func (r *ExpirationInPast) Setup(ns *naughty.Nameserver) []*naughty.Zone {
	name := dns.Fqdn(fmt.Sprintf("expiration-in-past.%s", ns.BaseZoneName))

	signer := naughty.NewSignerAutogenSingleDefault(name)
	callbacks := naughty.NewStandardCallbacks(signer)

	callbacks.Sign = func(m *dns.Msg) (*dns.Msg, error) {

		rrsetSigned := func(key *dns.DNSKEY, signer crypto.Signer, rrset []dns.RR, inception, expiration int64) (*dns.RRSIG, error) {
			// We move expiration to the past (and inception further back to align).
			inception = time.Now().Add(time.Hour * -48).Unix()
			expiration = time.Now().Add(time.Hour * -24).Unix()
			return naughty.SignRRSet(key, signer, rrset, inception, expiration)
		}

		return naughty.SignMsg(signer.Key(), signer.Signer(), m, rrsetSigned)
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logging.LogFmtValid, a.Header().Name))

	return []*naughty.Zone{zone}
}
