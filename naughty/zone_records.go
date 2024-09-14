package naughty

import (
	"github.com/miekg/dns"
	"slices"
	"strconv"
	"strings"
)

type records struct {
	collection []*record
}

type record struct {
	domain  string
	entries map[uint16][]dns.RR
}

type RecordSet []dns.RR

func (zoneRecords *records) get(rrname string, rrtype uint16) []dns.RR {
	i, found := slices.BinarySearchFunc(zoneRecords.collection, rrname, func(r *record, s string) int {
		return recordsCmp(r, &record{domain: s})
	})
	if !found {
		return nil
	}

	set, found := zoneRecords.collection[i].entries[rrtype]
	if !found {
		return nil
	}

	return set
}

func (zoneRecords *records) add(rr dns.RR) {
	if zoneRecords.collection == nil {
		zoneRecords.collection = make([]*record, 0)
	}

	domain := fqdn(rr.Header().Name)
	rrtype := rr.Header().Rrtype

	// Find the right record
	i, found := slices.BinarySearchFunc(zoneRecords.collection, domain, func(r *record, s string) int {
		return recordsCmp(r, &record{domain: s})
	})

	//---

	var r *record
	if found {
		r = zoneRecords.collection[i]
	} else {
		r = &record{domain: domain, entries: make(map[uint16][]dns.RR)}
		zoneRecords.collection = append(zoneRecords.collection, r)
		slices.SortFunc(zoneRecords.collection, recordsCmp)
	}

	//---

	if _, ok := r.entries[rrtype]; !ok {
		r.entries[rrtype] = make(RecordSet, 0)
	}

	r.entries[rrtype] = append(r.entries[rrtype], rr)
	r.entries[rrtype] = dns.Dedup(r.entries[rrtype], nil)
}

func recordsCmp(a, b *record) int {
	labelsA := dns.SplitDomainName(fqdn(a.domain))
	labelsB := dns.SplitDomainName(fqdn(b.domain))

	minLength := min(len(labelsA), len(labelsB))

	for i := 1; i <= minLength; i++ {
		labelA := labelsA[len(labelsA)-i]
		labelB := labelsB[len(labelsB)-i]

		// Convert labels to lowercase and decode escaped characters
		if strings.Contains(labelA, `\`) {
			labelA = decodeEscaped(labelA)
		}
		if strings.Contains(labelB, `\`) {
			labelB = decodeEscaped(labelB)
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
func decodeEscaped(label string) string {
	decoded := ""
	for i := 0; i < len(label); i++ {
		if label[i] == '\\' && i+3 < len(label) && isDigit(label[i+1]) && isDigit(label[i+2]) && isDigit(label[i+3]) {
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
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
