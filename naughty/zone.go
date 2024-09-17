package naughty

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

type Zone struct {
	Name string

	Callbacks *Callbacks

	NS  []GluedNS
	SOA *dns.SOA

	//records map[RRSetKey]RecordSet

	// a map of name, then type
	records RecordStore
}

type RecordSet []dns.RR

type RecordStore map[string]map[uint16]RecordSet

type wildcardMapping struct {
	qname    string
	wildcard string
}

type wildcardMappingHolder struct {
	mappings     []wildcardMapping
	moreMappings map[string]string
}

type wildcardUsage map[string]string

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
		//records: records{
		//	collection:      make([]*record, 0),
		//	nsec3Salt:       "baff1edd",
		//	nsec3Iterations: 2,
		//	origin:          name,
		//},
		records: make(RecordStore),

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

	zone.AddRecord(zone.SOA)

	// Add the zone's own nameservers
	for i, ns := range nameservers {
		// Add the records.
		zone.AddRecord(ns.A)
		zone.AddRecord(ns.NS)

		// Re-write the header to match the zone name
		ns.NS = dns.Copy(ns.NS).(*dns.NS)
		ns.NS.Header().Name = name
		zone.NS[i] = ns
		zone.AddRecord(ns.NS)
	}

	// Add the DNSKEYs.
	for _, dnskey := range callbacks.Keys() {
		zone.AddRecord(dnskey)
	}

	//---

	return zone
}

func (z *Zone) GetRecords(rrname string, rrtype uint16) []dns.RR {
	rrset, _ := z.records[rrname][rrtype]
	return rrset
}

func (z *Zone) GetTypesAndRecords(rrname string) map[uint16]RecordSet {
	rrset, _ := z.records[rrname]
	return rrset
}

func (z *Zone) AddRecord(r dns.RR) {
	qname := fqdn(r.Header().Name)
	qtype := r.Header().Rrtype

	if _, ok := z.records[qname]; !ok {
		z.records[qname] = make(map[uint16]RecordSet)
	}
	if _, ok := z.records[qname][qtype]; !ok {
		z.records[qname][qtype] = make(RecordSet, 0, 1)
	}

	z.records[qname][qtype] = append(z.records[qname][qtype], r)
	z.records[qname][qtype] = dns.Dedup(z.records[qname][qtype], nil)
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

func (z *Zone) populateResponse(qname string, qtype uint16, rmsg *dns.Msg, metadata *string, wildcards []wildcardMapping, holder *wildcardMappingHolder, wcUsage wildcardUsage) {
	// Assume DS for qname has already been checked.

	fmt.Printf("%s\n", qname)
	fmt.Printf("%p\n", wcUsage)
	//fmt.Printf("%s\n", *metadata)
	fmt.Println("----------------------------")

	// Do we have any records in the zone that exactly matches the QName and QType?
	if rrset := z.GetRecords(qname, qtype); rrset != nil {
		rmsg.Authoritative = true
		rmsg.Answer = append(rmsg.Answer, rrset...)
		return
	}

	// Do we have any wildcards that match the QName and QType?
	// TODO: The RRSIG label count needs amending!
	// TODO: we also need to add a NSEC(3) record into the Authority section, covering the qname.
	// 	https://datatracker.ietf.org/doc/html/rfc7129#section-5.3
	//if rrset := z.GetRecords("*."+z.Name, qtype); rrset != nil && qname != z.Name {

	// We can only have a wildcard if there are more labels in the question than zone name (* cannot catch the apex).
	if dns.CountLabel(qname) > dns.CountLabel(z.Name) {
		labelIndexes := dns.Split(qname)

		// Replaces the first label with *
		wildcardQname := "*." + qname[labelIndexes[1]:]

		if rrset := z.GetRecords(wildcardQname, qtype); rrset != nil {
			result := make([]dns.RR, len(rrset))
			for i, rr := range rrset {
				// We take a copy as we'll be amending the header later to match teh question.
				result[i] = dns.Copy(rr)
			}
			rmsg.Authoritative = true
			rmsg.Answer = append(rmsg.Answer, result...)

			// Record wildcard
			*metadata = wildcardQname + "/" + *metadata
			wildcards = append(wildcards, wildcardMapping{qname, wildcardQname})
			holder.mappings = append(holder.mappings, wildcardMapping{qname, wildcardQname})
			holder.moreMappings[wildcardQname] = qname
			wcUsage[wildcardQname] = qname

			return
		}
		if rrset := z.GetRecords(wildcardQname, dns.TypeCNAME); rrset != nil {
			target := rrset[0].(*dns.CNAME).Target
			if !strings.HasSuffix(target, ".") {
				target += "." + z.Name
			}

			rmsg.Authoritative = true
			for _, cname := range rrset {
				// We need to ensure the target is a fqdn, and the header later.
				cn := dns.Copy(cname)
				cn.(*dns.CNAME).Target = target
				rmsg.Answer = append(rmsg.Answer, cn)
			}

			// Record wildcard
			*metadata = wildcardQname + "/" + *metadata
			wildcards = append(wildcards, wildcardMapping{qname, wildcardQname})
			holder.mappings = append(holder.mappings, wildcardMapping{qname, wildcardQname})
			holder.moreMappings[wildcardQname] = qname
			wcUsage[wildcardQname] = qname

			z.populateResponse(target, qtype, rmsg, metadata, wildcards, holder, wcUsage)
			return
		}
	}

	// Do we have any records that match just the QName?
	if types := z.GetTypesAndRecords(qname); types != nil {
		// Is one of the types a CNAME?
		if rrset, _ := types[dns.TypeCNAME]; rrset != nil {

			target := rrset[0].(*dns.CNAME).Target
			if !strings.HasSuffix(target, ".") {
				target += "." + z.Name
			}

			rmsg.Authoritative = true
			for _, cname := range rrset {
				// We need to ensure the target is a fqdn
				cn := dns.Copy(cname)
				cn.(*dns.CNAME).Target = target
				rmsg.Answer = append(rmsg.Answer, cn)
			}

			z.populateResponse(target, qtype, rmsg, metadata, wildcards, holder, wcUsage)
			return
		} else if rrset, _ := types[dns.TypeNS]; rrset != nil && qname != z.Name {
			// Then we have an exact match on a delegation
			rmsg.Ns = append(rmsg.Ns, rrset...)
			return
		} else {
			// NODATA
			rmsg.Authoritative = true
			rmsg.Answer = append(rmsg.Ns, z.SOA)
			return
		}
	}

	// Do we have any NS records that match a suffix of the QName?
	for name := range IterateDownDomainHierarchy(qname) {
		if name == z.Name || !dns.IsSubDomain(z.Name, name) {
			// Break if we're now looking at this zone, or a parent of this zone.
			break
		}
		if rrset := z.GetRecords(name, dns.TypeNS); rrset != nil {
			// We're delegating...
			rmsg.Ns = append(rmsg.Ns, rrset...)
			return
		}
	}

	// NXDOMAIN
	rmsg.Authoritative = true
	rmsg.Rcode = dns.RcodeNameError
	rmsg.Answer = append(rmsg.Ns, z.SOA)

	return
}

func (z *Zone) Exchange(qmsg *dns.Msg) (*dns.Msg, error) {
	qname := fqdn(qmsg.Question[0].Name)
	qtype := qmsg.Question[0].Qtype

	if qtype == dns.TypeDS && qname == z.Name {
		// We should not be returning a DS record for ourselves.
		// Returning nil, nil will pass the request up to the parent zone.
		return nil, nil
	}

	rmsg := new(dns.Msg)
	rmsg.SetReply(qmsg)

	test := "test"
	wildcardsUsed := make([]wildcardMapping, 0)
	wildcardsUsedHolder := &wildcardMappingHolder{
		mappings:     make([]wildcardMapping, 0),
		moreMappings: make(map[string]string),
	}
	wcUsage := make(wildcardUsage)

	z.populateResponse(qname, qtype, rmsg, &test, wildcardsUsed, wildcardsUsedHolder, wcUsage)

	fmt.Printf("%p\n", wcUsage)
	//fmt.Printf("%s\n", test)
	fmt.Println("----------------------------")

	//---

	// See if we can help out with any glue.
	if len(rmsg.Ns) > 0 {
		glue := make([]dns.RR, 0)
		for _, rr := range append(rmsg.Answer, rmsg.Ns...) {
			if ns, ok := rr.(*dns.NS); ok {
				if rrset := z.GetRecords(ns.Ns, dns.TypeA); rrset != nil {
					glue = append(glue, rrset...)
				} else if rrset := z.GetRecords(ns.Ns, dns.TypeAAAA); rrset != nil {
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
		rmsg, err = z.Callbacks.DenyExistence(rmsg, z.records)
		if err != nil {
			return nil, err
		}

		rmsg, err = z.Callbacks.Sign(rmsg)
		if err != nil {
			return nil, err
		}

		rmsg.AuthenticatedData = true
	}

	//if synthesisedFromWildcard {
	//	// We need to set the correct header name.
	//	// We can't do it before we sign it though, otherwise the label count is wrong.
	//	//for _, rrset := range slices.Concat(rmsg.Answer, rmsg.Ns, rmsg.Extra) {
	//	//	if strings.HasPrefix(rrset.Header().Name, "*") {
	//	//		rrset.Header().Name = qmsg.Question[0].Name
	//	//	}
	//	//}
	//}

	//---

	// Finish. Have some tea.
	return rmsg, nil
}

func (z *Zone) Exchangexxx(qmsg *dns.Msg) (*dns.Msg, error) {
	// We lower-case the name here to work with DNS 0x20 encoding.
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

	if qname == z.Name {
		// We're looking at the zone's apex

		rmsg.Authoritative = true

		switch qtype {
		case dns.TypeSOA:
			rmsg.Answer = append(rmsg.Answer, z.SOA)
		case dns.TypeNS:
			for _, ns := range z.NS {
				rmsg.Answer = append(rmsg.Answer, ns.NS)
			}
		case dns.TypeDS:
			// We should not be returning a DS record for ourself.
			// We'll make an exception for the root zone. // TODO: should we?
			if rrset := z.GetRecords(qname, qtype); rrset != nil && qname == "." {
				rmsg.Authoritative = true
				rmsg.Answer = append(rmsg.Answer, rrset...)
			}

			// Returning nil, nil will pass the request up to the parent zone.
			return nil, nil
		default:
			if rrset := z.GetRecords(qname, qtype); rrset != nil {
				rmsg.Answer = append(rmsg.Answer, rrset...)
			}
		}

	} else {
		// Check if we have an exact match to the query
		if rrset := z.GetRecords(qname, qtype); rrset != nil {
			if qtype == dns.TypeNS {
				// Then we're delegating
				rmsg.Ns = append(rmsg.Ns, rrset...)
			} else {
				rmsg.Authoritative = true
				rmsg.Answer = append(rmsg.Answer, rrset...)
			}
		} else {
			// Else we might be able to delegate them in the right direction
			// We need to all zones from the FQDN in the question, down to this zone.
			for name := range IterateDownDomainHierarchy(qname) {
				if !dns.IsSubDomain(z.Name, name) {
					// Break if we're now looking at a parent of this zone.
					break
				} else if rrset := z.GetRecords(qname, dns.TypeNS); rrset != nil {
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
				if rrset := z.GetRecords(ns.Ns, dns.TypeA); rrset != nil {
					glue = append(glue, rrset...)
				} else if rrset := z.GetRecords(ns.Ns, dns.TypeAAAA); rrset != nil {
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
		rmsg, err = z.Callbacks.DenyExistence(rmsg, z.records)
		if err != nil {
			return nil, err
		}

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
