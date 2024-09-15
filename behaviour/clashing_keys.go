package behaviour

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"net"
	"strings"
)

/*
These keys are deliberately committed for testing purposes.

To understand how they were generated, see:
https://gist.github.com/nsmithuk/aecbffeb3dbbd20279181d3b57ba9de9.

These keys are pre-generated because finding matching keys is a non-deterministic task, and we cannot
reliably assume we'll always be able to generate them in a timely manner during Setup().
*/

// clashingKeys has keys with identical Flags, Protocol, Algorithm *and Tag*.
var clashingKeys = map[string]string{
	"QyNAHERauLBiVZua+9W1iIw+WG73bKMct3s8X9Phymc=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: lSRmSnXyVc1qQO+RJDft2cCnFONshJtWkKqrBsuqK7I=`,

	"OM3lk6zh0Dl1PqbNar3hsdlzOE1QdDyi9CYN4TNqaLI=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: Imk2wqR4GvwwRZ0BQpb31G17VMCGf30eTTAFGqrFUFI=`,

	"F1qCyN28RWK062XB30OsVAoG4iaSA8KxdDMf6vYDEmk=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: WSTJy/U+3PwhtCGTHgjldrOO1LfOWoI78fnmUEtF4Zg=`,

	"5fPWnkeiYYVBvqG3nU4EGXEyqUC6XJ1sE74LRgV0v6c=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: PfkPtaI+WMRGAb6H127uf5iSazdQ+/ymkC4Bbqtm3c4=`,

	"7Dm/9pFgK7nrgclE01lFNLR2EwIb50nH/6UXOugD3kk=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: miJcdKkOR61lea87kOkKK4DZvrZPI4gc9QB+qmQ+gBc=`,

	"w/IhaJ69VP2sC7QgMG+auWujvOg2GN9mzk4XXaFUd30=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: JenzYPD2q3ldCbCyhkqsX0e/WwHjGdTDIsL37BNNLUs=`,

	"k00ebWli/edH73cz7Ip4RTTjRYvuMU21Udu/jzyX/6M=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: ho9mEVla4jjpbC5DoebVqsmvqWtFc074kENkCW86gPg=`,
}

type ClashingKeys struct{}

func (t *ClashingKeys) Setup(ns *naughty.Nameserver) error {
	if len(clashingKeys) != 7 {
		return fmt.Errorf("expected 7 clashing keys, got %d", len(clashingKeys))
	}

	name := dns.Fqdn(fmt.Sprintf("clashing-keys.%s", ns.BaseZoneName))

	signers := make([]*naughty.SignerReaderSingle, len(clashingKeys))
	i := 0
	for public, secret := range clashingKeys {
		var err error
		signers[i], err = naughty.NewSignerReaderSingle(name, strings.NewReader(public), strings.NewReader(secret))
		if err != nil {
			return err
		}
		i++
	}

	// Sense check all the tags match.
	tag := signers[0].Key().KeyTag()
	for _, signer := range signers {
		if signer.Key().KeyTag() != tag {
			return fmt.Errorf("expected key tag %d, got %d", tag, signer.Key().KeyTag())
		}
	}

	//---

	// We use the "middle" key for actually signing.
	callbacks := naughty.NewStandardCallbacks(signers[3])

	// All keys are returned when requested.
	callbacks.Keys = func() []*dns.DNSKEY {
		keys := make([]*dns.DNSKEY, len(signers))
		for i, signer := range signers {
			keys[i] = signer.Key()
		}
		return keys
	}

	zone := naughty.NewZone(name, ns.NSRecords, callbacks)
	if err := ns.RegisterZone(zone); err != nil {
		naughty.Warn(fmt.Sprintf("Failed to register zone '%s': %s", name, err.Error()))
		return err
	}

	a := &dns.A{
		Hdr: naughty.NewHeader(fmt.Sprintf("test.%s", name), dns.TypeA),
		A:   net.ParseIP("192.0.2.53").To4(),
	}
	zone.AddRecord(a)

	naughty.Info(fmt.Sprintf(logFmtValid, a.Header().Name))

	return nil
}
