package naughty

import (
	"github.com/miekg/dns"
	"slices"
	"strconv"
	"strings"
)

func DefaultDenyExistenceNSEC(msg *dns.Msg, z *Zone, wildcardsUsed synthesisedResults) (*dns.Msg, error) {
	store := z.records
	qname := fqdn(msg.Question[0].Name)

	if msg.Rcode == dns.RcodeNameError {
		records := make([]dns.RR, 0, 2)
		records = append(records, store.getNSECRecord(qname))
		records = append(records, store.getNSECRecord(wildcardName(qname)))
		records = dns.Dedup(records, nil)
		msg.Ns = append(msg.Ns, records...)
	} else if len(msg.Ns) == 1 && msg.Ns[0].Header().Rrtype == dns.TypeSOA {
		// NODATA - we expect a single SOA record in Authority.
		msg.Ns = append(msg.Ns, store.getNSECRecord(qname))
	}

	if len(wildcardsUsed) > 0 {
		// https://datatracker.ietf.org/doc/html/rfc7129#section-5.3
		// When a wildcard was used, we need to add a NSEC record to prove the exact match on teh QName didn't exist.
		for _, qname := range wildcardsUsed {
			msg.Ns = append(msg.Ns, store.getNSECRecord(qname))
		}
	}

	return msg, nil
}

// getNSECRecord Returns a NSEC records that either matches (NODATA) for covers (NXDOMAIN) the given name.
func (store RecordStore) getNSECRecord(name string) dns.RR {
	names := make([]string, len(store))
	i := 0
	for k, _ := range store {
		names[i] = k
		i++
	}
	slices.SortFunc(names, canonicalCmp)

	// If found, n tells us where the matched record is.
	// If not found, n tells us where the record would be, thus the NSEC record n-1.
	n, found := slices.BinarySearchFunc(names, name, func(a string, b string) int {
		return canonicalCmp(a, b)
	})

	if !found {
		n--
		if n < 0 {
			// TODO: I suspect this is an error as nothing should be before the zone apex?
			n = len(names) - 1
		}
	}

	types := store[names[n]]
	typeBitMap := make([]uint16, len(types)+1)
	i = 0
	for t, _ := range types {
		typeBitMap[i] = t
		i++
	}
	typeBitMap[i] = dns.TypeNSEC // Attach this on.
	slices.Sort(typeBitMap)

	nsec := &dns.NSEC{
		Hdr:        NewHeader(names[n], dns.TypeNSEC),
		TypeBitMap: typeBitMap,
		NextDomain: names[(n+1)%len(names)],
	}
	return nsec
}

func canonicalCmp(a, b string) int {
	labelsA := dns.SplitDomainName(fqdn(a))
	labelsB := dns.SplitDomainName(fqdn(b))

	minLength := min(len(labelsA), len(labelsB))

	for i := 1; i <= minLength; i++ {
		labelA := labelsA[len(labelsA)-i]
		labelB := labelsB[len(labelsB)-i]

		// Convert labels to lowercase and decode escaped characters
		if strings.Contains(labelA, `\`) {
			labelA = canonicalDecodeEscaped(labelA)
		}
		if strings.Contains(labelB, `\`) {
			labelB = canonicalDecodeEscaped(labelB)
		}

		// Compare lexicographically
		if labelA != labelB {
			if labelA < labelB {
				return -1
			}
			return 1
		}
	}

	// If labels are identical so far, the shorter one sorts first
	if len(labelsA) < len(labelsB) {
		return -1
	} else if len(labelsA) > len(labelsB) {
		return 1
	}
	return 0
}

// Convert escaped octets (e.g., \001) to their byte values for comparison
func canonicalDecodeEscaped(label string) string {
	decoded := ""
	for i := 0; i < len(label); i++ {
		if label[i] == '\\' && i+3 < len(label) && canonicalIsDigit(label[i+1]) && canonicalIsDigit(label[i+2]) && canonicalIsDigit(label[i+3]) {
			// Decode escaped octet as a numeric value
			octetValue, err := strconv.Atoi(label[i+1 : i+4])
			if err == nil {
				decoded += string(rune(octetValue))
			}
			i += 3 // Skip the escaped characters
		} else {
			decoded += string(label[i])
		}
	}
	return decoded
}

// Check if a character is a digit
func canonicalIsDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
