package naughty

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/miekg/dns"
)

/*
SignerAutogenSingle Generates a CSK signer using the passed algorithm and bit count.
*/
type SignerAutogenSingle struct {
	key    *dns.DNSKEY
	signer crypto.Signer
	hash   uint8
}

// NewSignerAutogenSingleDefault Creates the default config - a ECDSAP256SHA256 CSK
func NewSignerAutogenSingleDefault(zone string) *SignerAutogenSingle {
	signer, err := NewSignerAutogenSingle(zone, dns.ECDSAP256SHA256, 256)
	if err != nil {
		panic(err)
	}
	return signer
}

func NewSignerAutogenSingle(zone string, algorithm uint8, bits int) (*SignerAutogenSingle, error) {
	dnskey := &dns.DNSKEY{
		Hdr:       NewHeader(zone, dns.TypeDNSKEY),
		Flags:     DnskeyFlagCsk,
		Protocol:  3,
		Algorithm: algorithm,
	}

	secret, err := dnskey.Generate(bits)
	if err != nil {
		panic(err)
	}

	var signer crypto.Signer
	switch s := secret.(type) {
	case *ecdsa.PrivateKey:
		signer = s
	case *rsa.PrivateKey:
		signer = s
	case ed25519.PrivateKey:
		signer = s
	default:
		return nil, fmt.Errorf("unknown secret type: %T", secret)
	}

	return &SignerAutogenSingle{
		hash:   dns.SHA256,
		signer: signer,
		key:    dnskey,
	}, nil
}

// SetDnsKeyFlag allows the DNSKEY flags to be amended.
func (s *SignerAutogenSingle) SetDnsKeyFlag(flag uint16) {
	s.key.Flags = flag
}

func (s *SignerAutogenSingle) Key() *dns.DNSKEY {
	return s.key
}

func (s *SignerAutogenSingle) Signer() crypto.Signer {
	return s.signer
}

func (s *SignerAutogenSingle) Keys() []*dns.DNSKEY {
	return []*dns.DNSKEY{s.key}
}

func (s *SignerAutogenSingle) DelegatedSingers() []*dns.DS {
	return []*dns.DS{s.key.ToDS(s.hash)}
}

func (s *SignerAutogenSingle) Sign(msg *dns.Msg) (*dns.Msg, error) {
	return SignMsg(s.key, s.signer, msg, SignRRSet)
}
