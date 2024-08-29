package naughty

import (
	"crypto/ecdsa"
	"github.com/miekg/dns"
	"time"
)

//------------------------------------------------------
// Simple

// SimpleSigner uses a single ECDSAP256SHA256 CSK to sign anything passed.
type SimpleSigner struct {
	key    *dns.DNSKEY
	signer *ecdsa.PrivateKey
	hash   uint8
}

func NewSimpleSigner(zone string) *SimpleSigner {
	dnskey := &dns.DNSKEY{
		Hdr:       NewHeader(zone, dns.TypeDNSKEY),
		Flags:     DnskeyFlagCsk,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}

	secret, err := dnskey.Generate(256)
	if err != nil {
		panic(err)
	}

	signer, _ := secret.(*ecdsa.PrivateKey)

	return &SimpleSigner{
		hash:   dns.SHA256,
		signer: signer,
		key:    dnskey,
	}
}

func (s *SimpleSigner) Keys() []*dns.DNSKEY {
	return []*dns.DNSKEY{s.key}
}

func (s *SimpleSigner) DelegatedSingers() []*dns.DS {
	return []*dns.DS{s.key.ToDS(s.hash)}
}

func (s *SimpleSigner) Sign(msg *dns.Msg) (*dns.Msg, error) {
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

func (s *SimpleSigner) signSet(rrset []dns.RR) (*dns.RRSIG, error) {
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
