package valid_negative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"math/rand"
	"net"
	"strings"
	"time"
)

/*
Helper functions to generate record sets for testing valid denial of existence proofs.

The hash values of NSEC3 records will change depending on the Base (Zone) Name that's set.
So to allow that to be dynamic, we need to find suitable records on Setup().
*/

func hash(name string) string {
	return strings.ToLower(dns.HashName(name, dns.SHA1, naughty.Nsec3Iterations, naughty.Nsec3Salt))
}

func pickRecordsCeAndNcnThenWc(zone string) []dns.RR {

	ce := hash(zone)
	wc := hash(fmt.Sprintf("*.%s", zone))
	test := hash(fmt.Sprintf("test.%s", zone))

	wcNameI := ""
	wcNameJ := ""

	otherNameI := ""
	otherNameJ := ""

	for i := 0; i < 1000; i++ {

		iName := fmt.Sprintf("%s.%s", randomString(3), zone)
		iHashedName := hash(iName)

		jName := fmt.Sprintf("%s.%s", randomString(3), zone)
		jHashedName := hash(jName)

		// We need ce & ncn one side of `test`, and wc the other

		// We'll look for EC first
		if isBetween(wc, iHashedName, jHashedName) {
			if !isBetween(ce, jHashedName, iHashedName) && !isBetween(test, jHashedName, iHashedName) {
				wcNameI = iName
				wcNameJ = jName
			}
		} else {
			if isBetween(ce, jHashedName, iHashedName) && isBetween(test, jHashedName, iHashedName) {
				otherNameI = iName
				otherNameJ = jName
			}
		}

		if len(wcNameI) > 0 && len(otherNameI) > 0 {
			break
		}

	}

	if !(len(wcNameI) > 0 && len(otherNameI) > 0) {
		panic("unable to find needed hashes")
	}

	return []dns.RR{
		&dns.A{
			Hdr: naughty.NewHeader(wcNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(wcNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
	}
}

func pickRecordsCeThenNcnAndWc(zone string) []dns.RR {

	ce := hash(zone)
	wc := hash(fmt.Sprintf("*.%s", zone))
	test := hash(fmt.Sprintf("test.%s", zone))

	wcNameI := ""
	wcNameJ := ""

	otherNameI := ""
	otherNameJ := ""

	for i := 0; i < 1000; i++ {

		iName := fmt.Sprintf("%s.%s", randomString(3), zone)
		iHashedName := hash(iName)

		jName := fmt.Sprintf("%s.%s", randomString(3), zone)
		jHashedName := hash(jName)

		// We need ce on one side of test `test`, and ncn & wc the other.

		if isBetween(ce, iHashedName, jHashedName) {
			if !isBetween(wc, jHashedName, iHashedName) && !isBetween(test, jHashedName, iHashedName) {
				wcNameI = iName
				wcNameJ = jName
			}
		} else {
			if isBetween(wc, jHashedName, iHashedName) && isBetween(test, jHashedName, iHashedName) {
				otherNameI = iName
				otherNameJ = jName
			}
		}

		if len(wcNameI) > 0 && len(otherNameI) > 0 {
			break
		}

	}

	if !(len(wcNameI) > 0 && len(otherNameI) > 0) {
		panic("unable to find needed hashes")
	}

	return []dns.RR{
		&dns.A{
			Hdr: naughty.NewHeader(wcNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(wcNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
	}
}

func pickRecordsCeThenWcThenNcn(zone string) []dns.RR {
	ce := hash(zone)
	wc := hash(fmt.Sprintf("*.%s", zone))
	test := hash(fmt.Sprintf("test.%s", zone))

	wcNameI := ""
	wcNameJ := ""

	otherNameI := ""
	otherNameJ := ""

	otherOtherNameI := ""
	otherOtherNameJ := ""

	for i := 0; i < 100000; i++ {

		iName := fmt.Sprintf("%s.%s", randomString(3), zone)
		iHashedName := hash(iName)

		jName := fmt.Sprintf("%s.%s", randomString(3), zone)
		jHashedName := hash(jName)

		// We need ce on one side of test `test`, and ncn & wc the other.

		if isBetween(ce, iHashedName, jHashedName) {
			if !isBetween(wc, jHashedName, iHashedName) && !isBetween(test, jHashedName, iHashedName) {
				wcNameI = iName
				wcNameJ = jName
			}
		} else if isBetween(wc, iHashedName, jHashedName) {
			if !isBetween(ce, jHashedName, iHashedName) && !isBetween(test, jHashedName, iHashedName) {
				otherNameI = iName
				otherNameJ = jName
			}
		} else {
			if !isBetween(ce, jHashedName, iHashedName) && !isBetween(wc, jHashedName, iHashedName) {
				otherOtherNameI = iName
				otherOtherNameJ = jName
			}
		}

		if len(wcNameI) > 0 && len(otherNameI) > 0 && len(otherOtherNameI) > 0 {
			break
		}

	}

	if !(len(wcNameI) > 0 && len(otherNameI) > 0 && len(otherOtherNameI) > 0) {
		panic("unable to find needed hashes")
	}

	return []dns.RR{
		&dns.A{
			Hdr: naughty.NewHeader(wcNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(wcNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherOtherNameI, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
		&dns.A{
			Hdr: naughty.NewHeader(otherOtherNameJ, dns.TypeA),
			A:   net.ParseIP("192.0.2.53").To4(),
		},
	}
}

func isBetween(s, a, b string) bool {
	// Check if s is between a and b, regardless of their order
	if a > b {
		a, b = b, a
	}
	return s > a && s < b
}

func strictIsBetween(s, a, b string) bool {
	return s > a && s < b
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
