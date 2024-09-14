package naughty

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

type Zone struct {
	Name string

	Callbacks *Callbacks

	NS  []GluedNS
	SOA *dns.SOA

	Records map[RecordKey]RecordSet
}

type RecordKey struct {
	Name string
	typ  uint16
}

type RecordSet []dns.RR

//---

func NewZone(name string, nameservers []GluedNS, callbacks *Callbacks) *Zone {
	name = dns.Fqdn(name)

	if len(nameservers) == 0 {
		panic("no nameservers defined")
	}

	zone := &Zone{
		Name:      name,
		NS:        make([]GluedNS, len(nameservers)),
		Callbacks: callbacks,
		Records:   make(map[RecordKey]RecordSet),

		SOA: &dns.SOA{
			Hdr:     NewHeader(name, dns.TypeSOA),
			Ns:      nameservers[0].NS.Header().Name, // Primary name server
			Mbox:    "naughty.nsmith.net.",           // Administrator's mailbox (replaced . with @)
			Serial:  uint32(time.Now().Unix()),       // Serial number (often the date followed by a counter)
			Refresh: 7200,                            // Refresh interval in seconds
			Retry:   3600,                            // Retry interval in seconds
			Expire:  1209600,                         // Expiry time in seconds
			Minttl:  60,                              // Minimum TTL in seconds
		},
	}

	//---

	// Add the zone's own nameservers
	for i, ns := range nameservers {
		// Add the records.
		zone.AddRecord(ns.A)
		zone.AddRecord(ns.NS)

		// Re-write the header to match the zone name
		ns.NS = dns.Copy(ns.NS).(*dns.NS)
		ns.NS.Header().Name = name
		zone.NS[i] = ns
	}

	// Add the Keys
	for _, dnskey := range callbacks.Keys() {
		zone.AddRecord(dnskey)
	}

	//---

	return zone
}

func (z *Zone) AddRecord(r dns.RR) {
	k := RecordKey{r.Header().Name, r.Header().Rrtype}

	if _, ok := z.Records[k]; !ok {
		z.Records[k] = make(RecordSet, 0)
	}

	z.Records[k] = append(z.Records[k], r)
	z.Records[k] = dns.Dedup(z.Records[k], nil)
}

func (z *Zone) AddRecords(r []dns.RR) {
	for _, rr := range r {
		z.AddRecord(rr)
	}
}

func (z *Zone) DelegateTo(child *Zone) {
	for _, ns := range child.NS {
		z.AddRecord(ns.A)
		z.AddRecord(ns.NS)
	}
	for _, ds := range child.Callbacks.DelegatedSingers() {
		z.AddRecord(ds)
	}
}

func (z *Zone) Query(qmsg *dns.Msg) (*dns.Msg, error) {
	// We lower-case the name here to work with DNS 0x20 encoding.
	q := RecordKey{strings.ToLower(qmsg.Question[0].Name), qmsg.Question[0].Qtype}

	rmsg := new(dns.Msg)
	rmsg.SetReply(qmsg)
	rmsg.RecursionAvailable = false
	rmsg.AuthenticatedData = false

	/*
		- The question name is for this zone's apex.
			- SOA and NS types are special?
			- DS records are special as although for this apex, it's served by this zone's parent.
	*/

	if q.Name == z.Name {
		// We're looking at the zone's apex

		rmsg.Authoritative = true

		switch q.typ {
		case dns.TypeSOA:
			rmsg.Answer = append(rmsg.Answer, z.SOA)
		case dns.TypeNS:
			for _, ns := range z.NS {
				rmsg.Answer = append(rmsg.Answer, ns.NS)
			}
		case dns.TypeDS:
			// We should not be returning a DS record for ourself.
			// We'll make an exception for the root zone. // TODO: should we?
			if records, ok := z.Records[q]; ok && q.Name == "." {
				rmsg.Authoritative = true
				rmsg.Answer = append(rmsg.Answer, records...)
			}

			// Returning nil, nil will pass the request up to the parent zone.
			return nil, nil
		default:
			if records, ok := z.Records[q]; ok {
				rmsg.Answer = append(rmsg.Answer, records...)
			}
		}

	} else {
		// Check if we have an exact match to the query
		if records, ok := z.Records[q]; ok {
			if q.typ == dns.TypeNS {
				// Then we're delegating
				rmsg.Ns = append(rmsg.Ns, records...)
			} else {
				rmsg.Authoritative = true
				rmsg.Answer = append(rmsg.Answer, records...)
			}
		} else {
			// Else we might be able to delegate them in the right direction
			// We need to all zones from the FQDN in the question, down to this zone.
			for name := range IterateDomainHierarchy(q.Name) {
				if !dns.IsSubDomain(z.Name, name) {
					// Break if we're now looking in a parent to this zone.
					break
				} else if records, ok = z.Records[RecordKey{name, dns.TypeNS}]; ok {
					rmsg.Ns = append(rmsg.Ns, records...)
					break
				}
			}
		}
	}

	if len(rmsg.Answer) == 0 && len(rmsg.Ns) == 0 {

		// If we've not found anything, add a SOA.
		// TODO and perhaps a NSEC?
		rmsg.Authoritative = true
		rmsg.Answer = append(rmsg.Answer, z.SOA)

	} else {
		// See if we can help out with any glue.
		glue := make([]dns.RR, 0)
		for _, rr := range append(rmsg.Answer, rmsg.Ns...) {
			if ns, ok := rr.(*dns.NS); ok {
				if records, ok := z.Records[RecordKey{ns.Ns, dns.TypeA}]; ok {
					glue = append(glue, records...)
				} else if records, ok := z.Records[RecordKey{ns.Ns, dns.TypeAAAA}]; ok {
					glue = append(glue, records...)
				}
			}
		}
		glue = dns.Dedup(glue, nil)
		if len(glue) > 0 {
			rmsg.Extra = append(rmsg.Extra, glue...)
		}
	}

	//if q.typ == dns.TypeNS && q.Name == z.Name {
	//
	//	// "My" NS is special...
	//	for _, ns := range z.NS {
	//		rmsg.Answer = append(rmsg.Answer, ns.NS)
	//	}
	//
	//} else if q.typ == dns.TypeSOA && q.Name == z.Name {
	//
	//	// If SOA, special...
	//	rmsg.Answer = append(rmsg.Answer, z.SOA)
	//
	//} else if q.typ == dns.TypeDS && q.Name == z.Name && q.Name != "." {
	//
	//	// We should not be returning a DS record for ourselves.
	//	// We'll make an exception for the root zone.
	//
	//	// Returning nil, nil will pass the request up to the parent zone.
	//	return nil, nil
	//
	//} else if records, ok := z.Records[q]; ok {
	//	// General case
	//
	//	if q.typ == dns.TypeNS {
	//		rmsg.Ns = append(rmsg.Ns, records...)
	//		rmsg.Authoritative = false
	//	} else {
	//		rmsg.Answer = append(rmsg.Answer, records...)
	//	}
	//
	//} else if records, ok := z.Records[RecordKey{q.Name, dns.TypeNS}]; ok {
	//	// Check if we're able to delegate the response elsewhere.
	//	rmsg.Ns = append(rmsg.Ns, records...)
	//	rmsg.Authoritative = false
	//	if records, ok := z.Records[RecordKey{q.Name, dns.TypeDS}]; ok {
	//		rmsg.Ns = append(rmsg.Ns, records...)
	//	}
	//} else {
	//	// When not found...
	//	rmsg.Ns = append(rmsg.Ns, z.SOA)
	//}

	//---

	//// If we have NS records set anywhere, add some glue if we can.
	//glue := make([]dns.RR, 0)
	//for _, rr := range append(rmsg.Answer, rmsg.Ns...) {
	//	if ns, ok := rr.(*dns.NS); ok {
	//		if records, ok := z.Records[RecordKey{ns.Ns, dns.TypeA}]; ok {
	//			glue = append(glue, records...)
	//		} else if records, ok := z.Records[RecordKey{ns.Ns, dns.TypeAAAA}]; ok {
	//			glue = append(glue, records...)
	//		}
	//	}
	//}
	//glue = dns.Dedup(glue, nil)
	//if len(glue) > 0 {
	//	rmsg.Extra = append(rmsg.Extra, glue...)
	//}

	//---

	if rmsg.Authoritative && Do(qmsg) {
		var err error
		rmsg, err = z.Callbacks.Sign(rmsg)
		if err != nil {
			return nil, err
		}
		rmsg.AuthenticatedData = true
	}

	//---

	// Finish. Have some tea.
	return rmsg, nil
}
