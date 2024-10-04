package naughty

import (
	"encoding/base32"
	"encoding/hex"
	"github.com/miekg/dns"
	"slices"
	"strings"
)

const (
	// Do not change these - some tests assume these specific valuse.

	Nsec3Salt       = "abcdef"
	Nsec3Iterations = uint16(2)
)

func DefaultDenyExistenceNSEC3(msg *dns.Msg, z *Zone, wildcardsUsed SynthesisedResults) (*dns.Msg, error) {
	store := z.Records
	qname := fqdn(msg.Question[0].Name)

	if msg.Rcode == dns.RcodeNameError {
		records := make([]dns.RR, 0, 3)

		// Closest Encloser
		records = append(records, store.GetNSEC3ClosestEncloserRecord(qname, z.Name))

		// The specific QName
		records = append(records, store.GetNSEC3Record(qname, z.Name))

		// The wildcard
		records = append(records, store.GetNSEC3Record(WildcardName(qname), z.Name))

		records = dns.Dedup(records, nil)
		msg.Ns = append(msg.Ns, records...)
	} else if len(msg.Ns) == 1 && msg.Ns[0].Header().Rrtype == dns.TypeSOA {
		// NODATA - we expect a single SOA record in Authority.
		msg.Ns = append(msg.Ns, store.GetNSEC3Record(qname, z.Name))
	}

	if len(wildcardsUsed) > 0 {
		// https://datatracker.ietf.org/doc/html/rfc7129#section-5.3
		// When a wildcard was used, we need to add a NSEC record to prove the exact match on the QName didn't exist.
		for _, qname := range wildcardsUsed {
			msg.Ns = append(msg.Ns, store.GetNSEC3Record(qname, z.Name))
		}
	}

	// If we're delegating, we expect a DS record.
	if countRecordsOfType(msg.Ns, dns.TypeNS) > 0 && countRecordsOfType(msg.Ns, dns.TypeDS) == 0 {
		msg.Ns = append(msg.Ns, store.GetNSEC3Record(qname, z.Name))
	}

	return msg, nil
}

func (store RecordStore) GetNSEC3ClosestEncloserRecord(name, zoneName string) dns.RR {
	for _, i := range dns.Split(name) {
		if _, ok := store[name[i:]]; ok {
			return store.GetNSEC3Record(name[i:], zoneName)
		}
	}

	return nil
}

type nsec3Map struct {
	digest   string
	original string
}

func (store RecordStore) GetNSEC3Record(name, zoneName string) dns.RR {
	names := make([]nsec3Map, len(store))
	i := 0
	for k, _ := range store {
		names[i] = nsec3Map{
			original: k,
			digest:   strings.ToLower(dns.HashName(k, dns.SHA1, Nsec3Iterations, Nsec3Salt)),
		}
		i++
	}
	slices.SortFunc(names, func(a, b nsec3Map) int {
		return strings.Compare(a.digest, b.digest)
	})

	hashedName := strings.ToLower(dns.HashName(name, dns.SHA1, Nsec3Iterations, Nsec3Salt))

	// If found, n tells us where the matched record is.
	// If not found, n tells us where the record would be, thus the NSEC record n-1.
	n, found := slices.BinarySearchFunc(names, hashedName, func(a nsec3Map, b string) int {
		return strings.Compare(a.digest, b)
	})

	if !found {
		n--
		if n < 0 {
			n = len(names) - 1
		}
	}

	// Note [...] the NSEC3 type itself will never be present in the Type Bit Maps.
	// https://datatracker.ietf.org/doc/html/rfc5155#section-7.1

	types := store[names[n].original]
	typeBitMap := make([]uint16, len(types))
	i = 0
	for t, _ := range types {
		typeBitMap[i] = t
		i++
	}
	//typeBitMap[i] = dns.TypeNSEC3 // See above comment.
	slices.Sort(typeBitMap)

	nextRecordHash := names[(n+1)%len(names)].digest
	nsec3 := &dns.NSEC3{
		Hdr:        NewHeader(names[n].digest+"."+zoneName, dns.TypeNSEC3),
		TypeBitMap: typeBitMap,
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: Nsec3Iterations,
		SaltLength: uint8(hex.DecodedLen(len(Nsec3Salt))),
		Salt:       Nsec3Salt,
		NextDomain: nextRecordHash,
		HashLength: uint8(base32.StdEncoding.DecodedLen(len(nextRecordHash))),
	}
	return nsec3
}
