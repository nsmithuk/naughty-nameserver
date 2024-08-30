package naughty

import "github.com/miekg/dns"

type Callbacks struct {
	// Message mutators
	PreSigning  func(*dns.Msg) *dns.Msg
	PostSigning func(*dns.Msg) *dns.Msg

	// Message signing
	Keys             func() []*dns.DNSKEY
	Sign             func(*dns.Msg) (*dns.Msg, error)
	DelegatedSingers func() []*dns.DS
}

func NewStandardCallbacks(signer Signer) *Callbacks {
	return &Callbacks{
		PreSigning:  func(m *dns.Msg) *dns.Msg { return m },
		PostSigning: func(m *dns.Msg) *dns.Msg { return m },

		Keys:             func() []*dns.DNSKEY { return signer.Keys() },
		DelegatedSingers: func() []*dns.DS { return signer.DelegatedSingers() },
		Sign:             func(m *dns.Msg) (*dns.Msg, error) { return signer.Sign(m) },
	}
}
