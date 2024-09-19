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

/*
SignerReaderSingle Generates a CSK signer using the passed algorithm and bit count.
*/
type SignerReaderSingle struct {
	key    *dns.DNSKEY
	signer crypto.Signer
	hash   uint8
}

func NewSignerReaderSingle(zone string, publicReader, secretReader io.Reader) (*SignerReaderSingle, error) {
	signer := &SignerReaderSingle{
		hash: dns.SHA256,
	}

	//---

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

	signer.key = &dns.DNSKEY{
		Hdr:       NewHeader(zone, dns.TypeDNSKEY),
		Flags:     DnskeyFlagKsk,
		Protocol:  3,
		Algorithm: uint8(algorithm),
		PublicKey: strings.TrimSpace(string(public)),
	}

	//---

	secret, err := signer.key.ReadPrivateKey(bytes.NewReader(secretBytes), "local io.Reader")
	if err != nil {
		return nil, err
	}

	switch s := secret.(type) {
	case *ecdsa.PrivateKey:
		signer.signer = s
	case *rsa.PrivateKey:
		signer.signer = s
	case ed25519.PrivateKey:
		signer.signer = s
	default:
		return nil, fmt.Errorf("unknown secret type: %T", secret)
	}

	return signer, nil
}

// SetDnsKeyFlag allows the DNSKEY flags to be amended.
func (s *SignerReaderSingle) SetDnsKeyFlag(flag uint16) {
	s.key.Flags = flag
}

func (s *SignerReaderSingle) Key() *dns.DNSKEY {
	return s.key
}

func (s *SignerReaderSingle) Signer() crypto.Signer {
	return s.signer
}

func (s *SignerReaderSingle) Keys() []*dns.DNSKEY {
	return []*dns.DNSKEY{s.key}
}

func (s *SignerReaderSingle) DelegatedSingers() []*dns.DS {
	ds := s.key.ToDS(s.hash)
	return []*dns.DS{ds}
}

func (s *SignerReaderSingle) Sign(msg *dns.Msg) (*dns.Msg, error) {
	return SignMsg(s.key, s.signer, msg, SignRRSet)
}
