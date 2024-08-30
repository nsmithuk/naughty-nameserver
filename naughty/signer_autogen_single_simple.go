package naughty

import (
	"github.com/miekg/dns"
)

// SignerAutogenSingleSimple uses a single ECDSAP256SHA256 CSK to sign anything passed.
type SignerAutogenSingleSimple struct {
	parent *SignerAutogenSingle
}

func NewSignerAutogenSingleSimple(zone string) *SignerAutogenSingleSimple {
	parent, err := NewSignerAutogenSingle(zone, dns.ECDSAP256SHA256, 256)
	if err != nil {
		panic(err)
	}

	return &SignerAutogenSingleSimple{
		parent: parent,
	}
}

// SetDnsKeyFlag allows the DNSKEY flags to be amended.
func (s *SignerAutogenSingleSimple) SetDnsKeyFlag(flag uint16) {
	s.parent.SetDnsKeyFlag(flag)
}

func (s *SignerAutogenSingleSimple) Keys() []*dns.DNSKEY {
	return s.parent.Keys()
}

func (s *SignerAutogenSingleSimple) DelegatedSingers() []*dns.DS {
	return s.parent.DelegatedSingers()
}

func (s *SignerAutogenSingleSimple) Sign(msg *dns.Msg) (*dns.Msg, error) {
	return s.parent.Sign(msg)
}
