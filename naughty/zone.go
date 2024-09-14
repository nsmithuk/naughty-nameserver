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

	//Records map[RecordKey]RecordSet

	records records
}

type RecordKey struct {
	Name string
	typ  uint16
}

//type records struct {
//	domain  string
//	entries map[uint16]RecordSet
//}

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
		//Records:   make(map[RecordKey]RecordSet),
		records: records{},

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
	z.records.add(r)
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

func (z *Zone) Exchange(qmsg *dns.Msg) (*dns.Msg, error) {
	// We lower-case the name here to work with DNS 0x20 encoding.
	q := RecordKey{strings.ToLower(qmsg.Question[0].Name), qmsg.Question[0].Qtype}

	qname := fqdn(qmsg.Question[0].Name)
	qtype := qmsg.Question[0].Qtype

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
			if rrset := z.records.get(qname, qtype); rrset != nil && q.Name == "." {
				rmsg.Authoritative = true
				rmsg.Answer = append(rmsg.Answer, rrset...)
			}

			// Returning nil, nil will pass the request up to the parent zone.
			return nil, nil
		default:
			if rrset := z.records.get(qname, qtype); rrset != nil {
				rmsg.Answer = append(rmsg.Answer, rrset...)
			}
		}

	} else {
		// Check if we have an exact match to the query
		//if records, ok := z.Records[q]; ok {
		if rrset := z.records.get(qname, qtype); rrset != nil {
			if q.typ == dns.TypeNS {
				// Then we're delegating
				rmsg.Ns = append(rmsg.Ns, rrset...)
			} else {
				rmsg.Authoritative = true
				rmsg.Answer = append(rmsg.Answer, rrset...)
			}
		} else {
			// Else we might be able to delegate them in the right direction
			// We need to all zones from the FQDN in the question, down to this zone.
			for name := range IterateDownDomainHierarchy(q.Name) {
				if !dns.IsSubDomain(z.Name, name) {
					// Break if we're now looking in a parent to this zone.
					break
				} else if rrset := z.records.get(qname, dns.TypeNS); rrset != nil {
					rmsg.Ns = append(rmsg.Ns, rrset...)
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
				if rrset := z.records.get(ns.Ns, dns.TypeA); rrset != nil {
					glue = append(glue, rrset...)
				} else if rrset := z.records.get(ns.Ns, dns.TypeAAAA); rrset != nil {
					glue = append(glue, rrset...)
				}
			}
		}
		glue = dns.Dedup(glue, nil)
		if len(glue) > 0 {
			rmsg.Extra = append(rmsg.Extra, glue...)
		}
	}

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
