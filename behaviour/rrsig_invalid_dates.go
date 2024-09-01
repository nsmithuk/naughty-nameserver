package behaviour

import (
	"crypto"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
	"time"
)

const (
	InvalidRRSigDatesInception  = iota // c0 == 0
	InvalidRRSigDatesExpiration = iota // c0 == 0
)

type InvalidRRSigDates struct{}

func (t *InvalidRRSigDates) Setup(ns *naughty.Nameserver) error {

	tests := []struct {
		name string
		typ  int
	}{
		{fmt.Sprintf("rrsig-inception-invalid.%s", ns.BaseZoneName), InvalidRRSigDatesInception},
		{fmt.Sprintf("rrsig-expiration-invalid.%s", ns.BaseZoneName), InvalidRRSigDatesExpiration},
	}

	for _, test := range tests {
		signer := naughty.NewSignerAutogenSingleDefault(test.name)

		callbacks := naughty.NewStandardCallbacks(signer)
		callbacks.Sign = func(msg *dns.Msg) (*dns.Msg, error) {
			return t.Sign(msg, test.typ, signer)
		}

		zone := naughty.NewZone(test.name, ns.NSRecords, callbacks)
		ns.BaseZone.DelegateTo(zone)
		ns.Zones[test.name] = zone

		a := &dns.A{
			Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", test.name), dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		}
		zone.AddRecord(a)

		naughty.Log.Infof(logFmtInvalid, a.Header().Name)
	}

	return nil
}

func (t *InvalidRRSigDates) Sign(msg *dns.Msg, typ int, signer *naughty.SignerAutogenSingle) (*dns.Msg, error) {
	return naughty.SignMsg(signer.Key(), signer.Signer(), msg, t.SignRRSet(typ))
}

func (t *InvalidRRSigDates) SignRRSet(typ int) naughty.SignRRSetSigner {
	return func(dnskey *dns.DNSKEY, signer crypto.Signer, rrs []dns.RR, inception, expiration int64) (*dns.RRSIG, error) {
		switch typ {
		case InvalidRRSigDatesInception:
			// inception is now one day in the future
			inception = time.Now().Add(time.Hour * 24).Unix()
			expiration = time.Now().Add(time.Hour * 48).Unix()
		case InvalidRRSigDatesExpiration:
			// expiration is now one day in the past.
			inception = time.Now().Add(time.Hour * -48).Unix()
			expiration = time.Now().Add(time.Hour * -24).Unix()
		}
		return naughty.SignRRSet(dnskey, signer, rrs, inception, expiration)
	}
}
