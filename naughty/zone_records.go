package naughty

//
//import (
//	"encoding/base32"
//	"encoding/hex"
//	"github.com/miekg/dns"
//	"slices"
//	"strconv"
//	"strings"
//)
//
//type records struct {
//	// Kept in a NSEC friendly order.
//	collection []*record
//	origin     string
//
//	nsec3OrderedCollection []nsec3OrderedRecord
//
//	nsec3Salt       string
//	nsec3Iterations uint16
//}
//
//type nsec3OrderedRecord struct {
//	digest string
//	record *record
//}
//
//type record struct {
//	domain string
//
//	nsec            *dns.NSEC
//	nsec3           *dns.NSEC3
//	nsec3HashedName string
//
//	entries map[uint16][]dns.RR
//}
//
//func (zoneRecords *records) get(rrname string, rrtype uint16) []dns.RR {
//
//	// Is it fast? No. Is it good enough? Yes.
//	i := slices.IndexFunc(zoneRecords.collection, func(r *record) bool {
//		return r.domain == rrname
//	})
//	if i < 0 {
//		return nil
//	}
//
//	set, found := zoneRecords.collection[i].entries[rrtype]
//	if !found {
//		return nil
//	}
//
//	return set
//}
//
//func (zoneRecords *records) add(rr dns.RR) {
//	if zoneRecords.collection == nil {
//		zoneRecords.collection = make([]*record, 0)
//	}
//
//	domain := fqdn(rr.Header().Name)
//	rrtype := rr.Header().Rrtype
//
//	i := slices.IndexFunc(zoneRecords.collection, func(r *record) bool {
//		return r.domain == domain
//	})
//
//	//---
//
//	var r *record
//	if i >= 0 {
//		r = zoneRecords.collection[i]
//	} else {
//		r = &record{domain: domain, entries: make(map[uint16][]dns.RR)}
//		zoneRecords.collection = append(zoneRecords.collection, r)
//
//		// This will ensure they're in the correct order, and the next domain is pre-mapped.
//		defer zoneRecords.remapNextDomain()
//		defer zoneRecords.remapNsec3OrderedCollection()
//	}
//
//	//---
//
//	if _, ok := r.entries[rrtype]; !ok {
//		r.entries[rrtype] = make(RecordSet, 0)
//	}
//
//	r.entries[rrtype] = append(r.entries[rrtype], rr)
//	r.entries[rrtype] = dns.Dedup(r.entries[rrtype], nil)
//
//	typeBitMap := make([]uint16, len(r.entries))
//	c := 0
//	for t, _ := range r.entries {
//		typeBitMap[c] = t
//		c++
//	}
//
//	//---
//
//	r.nsec = &dns.NSEC{
//		Hdr:        NewHeader(domain, dns.TypeNSEC),
//		TypeBitMap: typeBitMap,
//		// NextDomain is set in a separate step
//	}
//
//	r.nsec3HashedName = strings.ToLower(dns.HashName(domain, dns.SHA1, zoneRecords.nsec3Iterations, zoneRecords.nsec3Salt))
//	r.nsec3 = &dns.NSEC3{
//		Hdr:        NewHeader(r.nsec3HashedName+"."+zoneRecords.origin, dns.TypeNSEC3),
//		TypeBitMap: typeBitMap,
//		Hash:       dns.SHA1,
//		Flags:      0,
//		Iterations: zoneRecords.nsec3Iterations,
//		SaltLength: uint8(hex.DecodedLen(len(zoneRecords.nsec3Salt))),
//		Salt:       zoneRecords.nsec3Salt,
//		// NextDomain & HashLength is set in a separate step
//	}
//}
//
//func (zoneRecords *records) remapNextDomain() {
//	slices.SortFunc(zoneRecords.collection, recordsCmp)
//	for i, r := range zoneRecords.collection {
//		j := (i + 1) % len(zoneRecords.collection)
//		r.nsec.NextDomain = zoneRecords.collection[j].domain
//	}
//}
//
//func (zoneRecords *records) remapNsec3OrderedCollection() {
//	// We make the slice
//	zoneRecords.nsec3OrderedCollection = make([]nsec3OrderedRecord, len(zoneRecords.collection))
//	for i, r := range zoneRecords.collection {
//		zoneRecords.nsec3OrderedCollection[i] = nsec3OrderedRecord{
//			digest: r.nsec3HashedName,
//			record: r,
//		}
//	}
//
//	//---
//	// We sort the slice
//	slices.SortFunc(zoneRecords.nsec3OrderedCollection, func(a, b nsec3OrderedRecord) int {
//		return strings.Compare(a.digest, b.digest)
//	})
//
//	//---
//	// We map the next NextDomain
//	for i, r := range zoneRecords.nsec3OrderedCollection {
//		j := (i + 1) % len(zoneRecords.nsec3OrderedCollection)
//		r.record.nsec3.NextDomain = zoneRecords.nsec3OrderedCollection[j].record.nsec3HashedName
//		r.record.nsec3.HashLength = uint8(base32.StdEncoding.DecodedLen(len(zoneRecords.nsec3OrderedCollection[j].record.nsec3HashedName)))
//	}
//}
//
//func recordsCmp(a, b *record) int {
//	labelsA := dns.SplitDomainName(fqdn(a.domain))
//	labelsB := dns.SplitDomainName(fqdn(b.domain))
//
//	minLength := min(len(labelsA), len(labelsB))
//
//	for i := 1; i <= minLength; i++ {
//		labelA := labelsA[len(labelsA)-i]
//		labelB := labelsB[len(labelsB)-i]
//
//		// Convert labels to lowercase and decode escaped characters
//		if strings.Contains(labelA, `\`) {
//			labelA = decodeEscaped(labelA)
//		}
//		if strings.Contains(labelB, `\`) {
//			labelB = decodeEscaped(labelB)
//		}
//
//		// Compare lexicographically
//		if labelA != labelB {
//			if labelA < labelB {
//				return -1
//			}
//			return 1
//		}
//	}
//
//	// If labels are identical so far, the shorter one sorts first
//	if len(labelsA) < len(labelsB) {
//		return -1
//	} else if len(labelsA) > len(labelsB) {
//		return 1
//	}
//	return 0
//}
//
//// Convert escaped octets (e.g., \001) to their byte values for comparison
//func decodeEscaped(label string) string {
//	decoded := ""
//	for i := 0; i < len(label); i++ {
//		if label[i] == '\\' && i+3 < len(label) && isDigit(label[i+1]) && isDigit(label[i+2]) && isDigit(label[i+3]) {
//			// Decode escaped octet as a numeric value
//			octetValue, err := strconv.Atoi(label[i+1 : i+4])
//			if err == nil {
//				decoded += string(rune(octetValue))
//			}
//			i += 3 // Skip the escaped characters
//		} else {
//			decoded += string(label[i])
//		}
//	}
//	return decoded
//}
//
//// Check if a character is a digit
//func isDigit(b byte) bool {
//	return b >= '0' && b <= '9'
//}
