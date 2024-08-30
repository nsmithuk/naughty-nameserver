package naughty

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//------------------------------------------------------
// KSK From io.Reader, with generated ZSK.

type IoReaderSigner struct {
	zsk *dns.DNSKEY
	ksk *dns.DNSKEY

	kSigner crypto.Signer
	zSigner crypto.Signer

	hash uint8
}

func NewIoReaderSigner(zone string, publicReader, secretReader io.Reader) (Signer, error) {
	signer := &IoReaderSigner{
		hash: dns.SHA256,
	}

	//-----------------------------------
	// KSK

	public, err := io.ReadAll(publicReader)
	if err != nil {
		return nil, err
	}

	//---

	secretBytes, err := io.ReadAll(secretReader)
	if err != nil {
		return nil, err
	}

	// Detect the algorithm
	var algorithm int
	re := regexp.MustCompile(`(?i)Algorithm:\s*(\d+)\s*`)
	matches := re.FindStringSubmatch(string(secretBytes))

	if len(matches) >= 2 {
		algorithm, _ = strconv.Atoi(matches[1])
	}

	if algorithm <= 0 || algorithm > math.MaxUint8 {
		return nil, fmt.Errorf("unknown algorithm")
	}

	signer.ksk = &dns.DNSKEY{
		Hdr:       NewHeader(zone, dns.TypeDNSKEY),
		Flags:     DnskeyFlagKsk,
		Protocol:  3,
		Algorithm: uint8(algorithm),
		PublicKey: strings.TrimSpace(string(public)),
	}

	//---

	secret, err := signer.ksk.ReadPrivateKey(bytes.NewReader(secretBytes), "local io.Reader")
	if err != nil {
		return nil, err
	}

	signer.kSigner, _ = secret.(*ecdsa.PrivateKey)

	switch s := secret.(type) {
	case *ecdsa.PrivateKey:
		signer.kSigner = s
	case *rsa.PrivateKey:
		signer.kSigner = s
	case ed25519.PrivateKey:
		signer.kSigner = s
	default:
		return nil, fmt.Errorf("unknown secret type: %T", secret)
	}

	//-----------------------------------
	// ZSK

	signer.zsk = &dns.DNSKEY{
		Hdr:       NewHeader(zone, dns.TypeDNSKEY),
		Flags:     DnskeyFlagZsk,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}

	secret, err = signer.zsk.Generate(256)
	if err != nil {
		panic(err)
	}

	signer.zSigner, _ = secret.(*ecdsa.PrivateKey)

	return signer, nil
}

func (s *IoReaderSigner) Keys() []*dns.DNSKEY {
	return []*dns.DNSKEY{s.zsk, s.ksk}
}

func (s *IoReaderSigner) DelegatedSingers() []*dns.DS {
	return []*dns.DS{s.ksk.ToDS(s.hash)}
}

func (s *IoReaderSigner) Sign(msg *dns.Msg) (*dns.Msg, error) {
	for typ, rrset := range GroupRecordsByType(msg.Answer) {
		rrsig, err := s.signSet(rrset, typ)
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, rrsig)
	}
	for typ, rrset := range GroupRecordsByType(msg.Ns) {
		rrsig, err := s.signSet(rrset, typ)
		if err != nil {
			return nil, err
		}
		msg.Ns = append(msg.Ns, rrsig)
	}
	return msg, nil
}

func (s *IoReaderSigner) signSet(rrset []dns.RR, rrtype uint16) (*dns.RRSIG, error) {
	key := s.zsk
	signer := s.zSigner
	if rrtype == dns.TypeDNSKEY {
		key = s.ksk
		signer = s.kSigner
	}

	inception := time.Now().Unix() - (60 * 60 * 2)
	expiration := time.Now().Unix() + (60 * 60 * 2)
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
