package naughty

import (
	"github.com/miekg/dns"
)

type SignerAutogenPair struct {
	ksk  *SignerAutogenSingle
	zsk  *SignerAutogenSingle
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
		ksk:  ksk,
		zsk:  zsk,
	}, nil
}

func (s *SignerAutogenPair) Keys() []*dns.DNSKEY {
	return append(s.zsk.Keys(), s.ksk.Keys()...)
}

func (s *SignerAutogenPair) DelegatedSingers() []*dns.DS {
	return s.ksk.DelegatedSingers()
}

func (s *SignerAutogenPair) Sign(msg *dns.Msg) (*dns.Msg, error) {
	if ContainsType(msg.Answer, dns.TypeDNSKEY) {
		return s.ksk.Sign(msg)
	}
	return s.zsk.Sign(msg)
}
