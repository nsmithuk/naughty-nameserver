package naughty

import (
	"github.com/miekg/dns"
	"iter"
	"strings"
)

func IterateDownDomainHierarchy(domain string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if domain == "" {
			return
		}

		domain = fqdn(domain)

		// We add an index as we want root (.) returned at the end.
		indexes := append(dns.Split(domain), len(domain)-1)

		for _, i := range indexes {
			if !yield(domain[i:]) {
				return
			}
		}
	}
}

func fqdn(name string) string {
	return dns.Fqdn(strings.ToLower(name))
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

// Do Has the DO bit been set on the question
func Do(msg *dns.Msg) bool {
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			return opt.Do()
		}
	}
	return false
}
