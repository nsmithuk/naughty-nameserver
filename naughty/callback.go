package naughty

import "github.com/miekg/dns"

type Callbacks struct {
	// Message signing
	Keys             func() []*dns.DNSKEY
	Sign             func(*dns.Msg) (*dns.Msg, error)
	DelegatedSingers func() []*dns.DS
	DenyExistence    func(*dns.Msg, *Zone, SynthesisedResults) (*dns.Msg, error)
}

func NewStandardCallbacks(signer Signer) *Callbacks {
	return &Callbacks{
		Keys:             func() []*dns.DNSKEY { return signer.Keys() },
		DelegatedSingers: func() []*dns.DS { return signer.DelegatedSingers() },
		Sign:             func(m *dns.Msg) (*dns.Msg, error) { return signer.Sign(m) },
		DenyExistence:    DefaultDenyExistenceNSEC,
	}
}
