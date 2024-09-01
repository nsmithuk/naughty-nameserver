package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
	"slices"
)

/*
TwoValidZsks uses two ZSKs, and one KSK.

Both ZSKs will be used to sign the RR, resulting in there being two valid RRSIGs for the A record.
The KSK will operate as normal.
*/
type TwoValidZsks struct {
	ksk  *naughty.SignerAutogenSingle
	zsk1 *naughty.SignerAutogenSingle
	zsk2 *naughty.SignerAutogenSingle
}

func (t *TwoValidZsks) Setup(ns *naughty.Nameserver) error {

	name := dns.Fqdn(fmt.Sprintf("two-valid-zsks.%s", ns.BaseZoneName))

	//---

	t.ksk = naughty.NewSignerAutogenSingleDefault(name)
	t.ksk.SetDnsKeyFlag(naughty.DnskeyFlagKsk)

	t.zsk1 = naughty.NewSignerAutogenSingleDefault(name)
	t.zsk1.SetDnsKeyFlag(naughty.DnskeyFlagZsk)

	t.zsk2 = naughty.NewSignerAutogenSingleDefault(name)
	t.zsk2.SetDnsKeyFlag(naughty.DnskeyFlagZsk)

	//---

	// Note that we use "ourselves" as the Signer.
	zone := naughty.NewZone(name, ns.NSRecords, naughty.NewStandardCallbacks(t))
	ns.BaseZone.DelegateTo(zone)
	ns.Zones[name] = zone

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Log.Infof(logFmtValid, a.Header().Name)

	return nil
}

func (t *TwoValidZsks) Keys() []*dns.DNSKEY {
	return append(append(t.ksk.Keys(), t.zsk1.Keys()...), t.zsk2.Keys()...)
}
func (t *TwoValidZsks) DelegatedSingers() []*dns.DS {
	return t.ksk.DelegatedSingers()
}
func (t *TwoValidZsks) Sign(msg *dns.Msg) (*dns.Msg, error) {
	// If we have DNSKEYs in the answer...
	if _, ok := naughty.GroupRecordsByType(msg.Answer)[dns.TypeDNSKEY]; ok {
		return t.ksk.Sign(msg)
	}

	msg1, err := t.zsk1.Sign(msg.Copy())
	if err != nil {
		return nil, err
	}

	msg2, err := t.zsk2.Sign(msg.Copy())
	if err != nil {
		return nil, err
	}

	msg.Answer = slices.Concat(msg1.Answer, msg2.Answer)
	msg.Extra = slices.Concat(msg1.Extra, msg2.Extra)
	msg.Ns = slices.Concat(msg1.Ns, msg2.Ns)

	msg.Answer = dns.Dedup(msg.Answer, nil)
	msg.Extra = dns.Dedup(msg.Extra, nil)
	msg.Ns = dns.Dedup(msg.Ns, nil)

	return msg, nil
}
