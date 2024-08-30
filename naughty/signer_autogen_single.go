package naughty

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/miekg/dns"
	"time"
)

/*
SignerAutogenSingle Generates a CSK signer using the passed algorithm and bit count.
*/
type SignerAutogenSingle struct {
	key    *dns.DNSKEY
	signer crypto.Signer
	hash   uint8
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

func (s *SignerAutogenSingle) Keys() []*dns.DNSKEY {
	return []*dns.DNSKEY{s.key}
}

func (s *SignerAutogenSingle) DelegatedSingers() []*dns.DS {
	return []*dns.DS{s.key.ToDS(s.hash)}
}

func (s *SignerAutogenSingle) Sign(msg *dns.Msg) (*dns.Msg, error) {
	for _, rrset := range GroupRecordsByType(msg.Answer) {
		rrsig, err := s.signSet(rrset)
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, rrsig)
	}
	for _, rrset := range GroupRecordsByType(msg.Ns) {
		rrsig, err := s.signSet(rrset)
		if err != nil {
			return nil, err
		}
		msg.Ns = append(msg.Ns, rrsig)
	}
	return msg, nil
}

func (s *SignerAutogenSingle) signSet(rrset []dns.RR) (*dns.RRSIG, error) {
	inception := time.Now().Unix() - (60 * 60 * 2)
	expiration := time.Now().Unix() + (60 * 60 * 2)
	rrsig := &dns.RRSIG{
		Hdr:        NewHeader("", 0), // Values are set by Sign()
		Inception:  uint32(inception),
		Expiration: uint32(expiration),
		KeyTag:     s.key.KeyTag(),
		SignerName: s.key.Header().Name,
		Algorithm:  s.key.Algorithm,
	}
	err := rrsig.Sign(s.signer, rrset)
	return rrsig, err
}
