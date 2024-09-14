package naughty

import (
	"crypto"
	"github.com/miekg/dns"
	"time"
)

type Signer interface {
	Keys() []*dns.DNSKEY
	Sign(*dns.Msg) (*dns.Msg, error)
	DelegatedSingers() []*dns.DS
}

type SignRRSetSigner func(*dns.DNSKEY, crypto.Signer, []dns.RR, int64, int64) (*dns.RRSIG, error)

func SignMsg(key *dns.DNSKEY, signer crypto.Signer, msg *dns.Msg, rrsetSigner SignRRSetSigner) (*dns.Msg, error) {
	inception := time.Now().Add(time.Hour * -24).Unix()
	expiration := time.Now().Add(time.Hour * 24).Unix()

	for _, rrset := range GroupRecordsByType(msg.Answer) {
		rrsig, err := rrsetSigner(key, signer, rrset, inception, expiration)
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, rrsig)
	}

	for t, rrset := range GroupRecordsByType(msg.Ns) {
		if t == dns.TypeNS {
			// We don't sign NS records in the authority section.
			continue
		}
		rrsig, err := rrsetSigner(key, signer, rrset, inception, expiration)
		if err != nil {
			return nil, err
		}
		msg.Ns = append(msg.Ns, rrsig)
	}

	return msg, nil
}

func SignRRSet(key *dns.DNSKEY, signer crypto.Signer, rrset []dns.RR, inception, expiration int64) (*dns.RRSIG, error) {
	rrsig := &dns.RRSIG{
		Hdr:        NewHeader("", 0), // Values are set by Sign()
		Inception:  uint32(inception),
		Expiration: uint32(expiration),
		KeyTag:     key.KeyTag(),
		SignerName: key.Header().Name,
		Algorithm:  key.Algorithm,
	}
	err := rrsig.Sign(signer, rrset)
	return rrsig, err
}
