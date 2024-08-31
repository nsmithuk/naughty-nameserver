package naughty

import (
	"github.com/miekg/dns"
)

type SignerAutogenPair struct {
	Ksk  *SignerAutogenSingle
	Zsk  *SignerAutogenSingle
	hash uint8
}

func NewSignerAutogenPair(zone string, kskAlgorithm uint8, kskBits int, zskAlgorithm uint8, zskBits int) (*SignerAutogenPair, error) {
	ksk, err := NewSignerAutogenSingle(zone, kskAlgorithm, kskBits)
	if err != nil {
		return nil, err
	}
	ksk.SetDnsKeyFlag(DnskeyFlagKsk)

	//---

	zsk, err := NewSignerAutogenSingle(zone, zskAlgorithm, zskBits)
	if err != nil {
		return nil, err
	}
	zsk.SetDnsKeyFlag(DnskeyFlagZsk)

	//---

	return &SignerAutogenPair{
		hash: dns.SHA256,
		Ksk:  ksk,
		Zsk:  zsk,
	}, nil
}

func (s *SignerAutogenPair) Keys() []*dns.DNSKEY {
	return append(s.Zsk.Keys(), s.Ksk.Keys()...)
}

func (s *SignerAutogenPair) DelegatedSingers() []*dns.DS {
	return s.Ksk.DelegatedSingers()
}

func (s *SignerAutogenPair) Sign(msg *dns.Msg) (*dns.Msg, error) {
	if ContainsType(msg.Answer, dns.TypeDNSKEY) {
		return s.Ksk.Sign(msg)
	}
	return s.Zsk.Sign(msg)
}
