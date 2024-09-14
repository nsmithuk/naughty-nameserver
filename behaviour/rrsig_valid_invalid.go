package behaviour

import (
	"crypto"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
	"slices"
)

type ValidInvalidRRSig string

func (t *ValidInvalidRRSig) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("one-valid-one-invalid-rrsig.%s", ns.BaseZoneName))

	signer1 := naughty.NewSignerAutogenSingleDefault(name)
	signer2 := naughty.NewSignerAutogenSingleDefault(name)

	callbacks := naughty.NewStandardCallbacks(signer1)
	callbacks.Keys = func() []*dns.DNSKEY {
		return append(signer1.Keys(), signer2.Keys()...)
	}
	callbacks.DelegatedSingers = func() []*dns.DS {
		return append(signer1.DelegatedSingers(), signer2.DelegatedSingers()...)
	}

	callbacks.Sign = func(msg *dns.Msg) (*dns.Msg, error) {
		msg1, err := signer1.Sign(msg.Copy())
		if err != nil {
			return nil, err
		}

		msg2 := new(dns.Msg)

		// If they're asking for the A record.
		if msg.Question[0].Qtype == dns.TypeA && len(msg.Answer) > 0 {
			// The second signature will have expired.
			msg2 = msg.Copy()
			msg2.Answer[0].(*dns.A).A = net.ParseIP("192.0.2.58").To4()
			msg2, err = naughty.SignMsg(signer2.Key(), signer2.Signer(), msg2, t.SignRRSet)
			if err != nil {
				return nil, err
			}
			msg2.Answer[0] = msg.Answer[0]
		}

		msg.Answer = slices.Concat(msg1.Answer, msg2.Answer)
		msg.Extra = slices.Concat(msg1.Extra, msg2.Extra)
		msg.Ns = slices.Concat(msg1.Ns, msg2.Ns)

		msg.Answer = dns.Dedup(msg.Answer, nil)
		msg.Extra = dns.Dedup(msg.Extra, nil)
		msg.Ns = dns.Dedup(msg.Ns, nil)

		return msg, nil
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logFmtValid, a.Header().Name))

	return nil
}

func (t *ValidInvalidRRSig) SignRRSet(dnskey *dns.DNSKEY, signer crypto.Signer, rrs []dns.RR, inception, expiration int64) (*dns.RRSIG, error) {
	// Signs with an expired date.
	//inception = time.Now().Add(time.Hour * -48).Unix()
	//expiration = time.Now().Add(time.Hour * -24).Unix()
	return naughty.SignRRSet(dnskey, signer, rrs, inception, expiration)
}
