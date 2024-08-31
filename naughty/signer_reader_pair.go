package naughty

import (
	"github.com/miekg/dns"
	"io"
)

//------------------------------------------------------
// KSK From io.Reader, with generated ZSK.

type SignerReaderPair struct {
	Ksk  *SignerReaderSingle
	Zsk  *SignerAutogenSingle
	hash uint8
}

func NewSignerReaderPair(zone string, publicReader, secretReader io.Reader) (*SignerReaderPair, error) {
	ksk, err := NewSignerReaderSingle(zone, publicReader, secretReader)
	if err != nil {
		return nil, err
	}
	ksk.SetDnsKeyFlag(DnskeyFlagKsk)

	//---

	zsk := NewSignerAutogenSingleDefault(zone)
	zsk.SetDnsKeyFlag(DnskeyFlagZsk)

	//---

	return &SignerReaderPair{
		hash: dns.SHA256,
		Ksk:  ksk,
		Zsk:  zsk,
	}, nil
}

func (s *SignerReaderPair) Keys() []*dns.DNSKEY {
	return append(s.Zsk.Keys(), s.Ksk.Keys()...)
}

func (s *SignerReaderPair) DelegatedSingers() []*dns.DS {
	return s.Ksk.DelegatedSingers()
}

func (s *SignerReaderPair) Sign(msg *dns.Msg) (*dns.Msg, error) {
	if ContainsType(msg.Answer, dns.TypeDNSKEY) {
		return s.Ksk.Sign(msg)
	}
	return s.Zsk.Sign(msg)
}
