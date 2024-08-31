package naughty

import (
	"github.com/miekg/dns"
	"io"
)

//------------------------------------------------------
// KSK From io.Reader, with generated ZSK.

type SignerReaderPair struct {
	ksk  *SignerReaderSingle
	zsk  *SignerAutogenSingle
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
		ksk:  ksk,
		zsk:  zsk,
	}, nil
}

func (s *SignerReaderPair) Keys() []*dns.DNSKEY {
	return append(s.zsk.Keys(), s.ksk.Keys()...)
}

func (s *SignerReaderPair) DelegatedSingers() []*dns.DS {
	return s.ksk.DelegatedSingers()
}

func (s *SignerReaderPair) Sign(msg *dns.Msg) (*dns.Msg, error) {
	if ContainsType(msg.Answer, dns.TypeDNSKEY) {
		return s.ksk.Sign(msg)
	}
	return s.zsk.Sign(msg)
}
