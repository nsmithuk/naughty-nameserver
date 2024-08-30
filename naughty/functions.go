package naughty

import (
	"github.com/miekg/dns"
	"iter"
	"strings"
)

func IterateDomainHierarchy(domain string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if domain == "" {
			return
		}

		domain = strings.TrimSuffix(domain, ".")
		labels := dns.SplitDomainName(domain)

		for i := 0; i <= len(labels); i++ {
			var result string
			if i == len(labels) {
				// The root is a special case.
				result = "."
			} else {
				// Join the last i labels.
				result = strings.Join(labels[i:], ".") + "."
			}
			if !yield(result) {
				return
			}
		}

	}
}

func NewHeader(name string, rrtype uint16) dns.RR_Header {
	name = dns.Fqdn(name)
	return dns.RR_Header{
		Name:   name,          // The domain name for the SOA record
		Rrtype: rrtype,        // The type of DNS record
		Class:  dns.ClassINET, // The class of the record (usually IN for Internet)
		Ttl:    300,           // Time to live in seconds
	}
}

func ContainsType(rrset []dns.RR, t uint16) bool {
	_, ok := GroupRecordsByType(rrset)[t]
	return ok
}

func GroupRecordsByType(rrset []dns.RR) map[uint16][]dns.RR {
	results := make(map[uint16][]dns.RR)
	for _, rr := range rrset {
		t := rr.Header().Rrtype
		if _, ok := results[t]; !ok {
			results[t] = []dns.RR{}
		}
		results[t] = append(results[t], rr)
	}
	return results
}
