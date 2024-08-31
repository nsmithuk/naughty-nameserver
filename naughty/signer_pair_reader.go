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
)

//------------------------------------------------------
// KSK From io.Reader, with generated ZSK.

// TODO: This can likely be composed of two other Single Key signers now.

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
	if ContainsType(msg.Answer, dns.TypeDNSKEY) {
		return SignMsg(s.ksk, s.kSigner, msg, SignRRSet)
	}
	return SignMsg(s.zsk, s.zSigner, msg, SignRRSet)
}
