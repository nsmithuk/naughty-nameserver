package naughty

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
)

const (
	DnskeyFlagZsk uint16 = 256 // Zone Signing Key
	DnskeyFlagKsk uint16 = 257 // Key Signing Key
	DnskeyFlagCsk uint16 = 257 // Key Signing Key
)

type Nameserver struct {
	RootZone     *Zone
	BaseZone     *Zone
	BaseZoneName string
	NSRecords    []GluedNS
	Zones        map[string]*Zone
}

type GluedNS struct {
	NS *dns.NS
	A  *dns.A
}

func NewNameserver(baseZoneName string, nsIPv4s []string) *Nameserver {
	if len(nsIPv4s) == 0 {
		panic("no nsIPv4s set")
	}

	records := make([]GluedNS, len(nsIPv4s))
	for i, ip := range nsIPv4s {
		host := fmt.Sprintf("ns%d.%s", i+1, baseZoneName)

		Info(fmt.Sprintf("Nameserver %d: %s\n", i+1, host))

		addr := net.ParseIP(ip).To4()
		if addr == nil {
			panic(fmt.Sprintf("invalid ip address %s", ip))
		}

		records[i] = GluedNS{
			A: &dns.A{
				Hdr: NewHeader(host, dns.TypeA),
				A:   addr,
			},
			NS: &dns.NS{
				Hdr: NewHeader(host, dns.TypeNS),
				Ns:  host,
			},
		}
	}

	server := &Nameserver{
		BaseZoneName: baseZoneName,
		NSRecords:    records,
		Zones:        make(map[string]*Zone),
	}

	server.buildInitialZones()

	return server
}

func (ns *Nameserver) RegisterZone(new *Zone) error {
	return ns.RegisterToZone(new, ns.BaseZone)
}

func (ns *Nameserver) RegisterToZone(new *Zone, existing *Zone) error {

	if _, ok := ns.Zones[new.Name]; ok {
		return fmt.Errorf("zone with name %s already exists", new.Name)
	}

	ns.Zones[new.Name] = new
	existing.DelegateTo(new)

	return nil
}

func (ns *Nameserver) AddBehaviours(behaviours []BehaviourFactory) error {
	var err error
	for _, b := range behaviours {

		zones := b.Setup(ns)

		for _, z := range zones {
			err = ns.RegisterZone(z)
			if err != nil {
				return err
			}
		}

	}
	return nil
}

func (ns *Nameserver) RootDelegatedSingers() []*dns.DS {
	return ns.RootZone.Callbacks.DelegatedSingers()
}

func (ns *Nameserver) BaseDelegatedSingers() []*dns.DS {
	return ns.BaseZone.Callbacks.DelegatedSingers()
}

func (ns *Nameserver) Exchange(qmsg *dns.Msg) (*dns.Msg, error) {
	name := fqdn(qmsg.Question[0].Name)

	/*
		We want to find the most specific zone for the Question.

		Break the name into labels, then loops through and find the first match. For example:
		deep.invalid.naughty-nameserver.com.
		invalid.naughty-nameserver.com.
		naughty-nameserver.com.
		com.
		.
	*/
	for zoneName := range IterateDownDomainHierarchy(name) {

		// TODO: catch DS lookups here?

		// Is there is a zone with this name...
		// Note that this map does not change once the server is setup, thus we don't need any thread-safe locking here.
		if zone, ok := ns.Zones[zoneName]; ok {
			rmsg, err := zone.Exchange(qmsg)

			// If one, or both, are not nil, return.
			if rmsg != nil || err != nil {
				return rmsg, err
			}

			// Else we stay in the loop as a parent may have an answer.
			// This is the case for DS records. for example.
		}
	}

	// Then not found.
	rmsg := new(dns.Msg)
	rmsg.SetReply(qmsg)
	rmsg.Authoritative = false
	rmsg.RecursionAvailable = false
	rmsg.Rcode = dns.RcodeRefused

	return rmsg, fmt.Errorf("no response found for %s", name)
}

func (ns *Nameserver) buildInitialZones() {
	/*
		Creates the zone for the base domain. For example: naughy-nameserver.com.

		Also creates a zone for each label down to, and including, the root zone.
		So with the example naughy-nameserver.com., the following zoes are created (and liked with NS deligation and DS records).
			- naughy-nameserver.com.
			- com.
			- .
	*/
	var last *Zone
	//for name := range IterateDownDomainHierarchy(ns.BaseZoneName) {
	for _, name := range []string{ns.BaseZoneName} {
		var signer Signer
		switch name {
		case ns.BaseZoneName:
			signer, _ = NewSignerReaderPair(
				name,
				strings.NewReader(basePublic),
				strings.NewReader(baseSecret),
			)
		case ".":
			signer, _ = NewSignerReaderPair(
				name,
				strings.NewReader(rootPublic),
				strings.NewReader(rootSecret),
			)
		default:
			signer = NewSignerAutogenSingleDefault(name)
		}

		ns.Zones[name] = NewZone(name, ns.NSRecords, NewStandardCallbacks(signer))

		if last != nil {
			ns.Zones[name].DelegateTo(last)
		}

		if name == "." {
			// If we're at the root, add our DS records to the actual zone, to ensure it's returned.
			for _, ds := range ns.Zones[name].Callbacks.DelegatedSingers() {
				ns.Zones[name].AddRecord(ds)
			}
			ns.RootZone = ns.Zones[name]
			Debug(fmt.Sprintf("--------------------------------------\n"))
			Debug(fmt.Sprintf("Root Details for %s\n", name))
			for _, key := range signer.Keys() {
				Debug(fmt.Sprintf("Key:\t%s (KeyTag: %d)\n", key.String(), key.KeyTag()))
			}
			Debug(fmt.Sprintf("DS:\t%s\n", signer.DelegatedSingers()[0]))
			Debug(fmt.Sprintf("--------------------------------------\n"))
		} else if name == ns.BaseZoneName {
			ns.BaseZone = ns.Zones[name]
			Info(fmt.Sprintf("--------------------------------------\n"))
			Info(fmt.Sprintf("KSK Details for %s\n", name))
			for _, key := range signer.Keys() {
				Info(fmt.Sprintf("Key:\t%s (KeyTag: %d)\n", key.String(), key.KeyTag()))
			}
			Info(fmt.Sprintf("DS:\t%s\n", signer.DelegatedSingers()[0]))
			Info(fmt.Sprintf("--------------------------------------\n"))

			//---
			// External test
			ns.Zones[name].AddRecord(&dns.NS{
				Hdr: NewHeader(fmt.Sprintf("aws.%s", strings.TrimRight(name, ".")), dns.TypeNS),
				Ns:  "ns-463.awsdns-57.com.",
			})

		}

		ns.Zones[name].AddRecord(&dns.A{
			Hdr: NewHeader(fmt.Sprintf("test.%s", strings.TrimRight(name, ".")), dns.TypeA),
			A:   net.ParseIP("192.0.2.53"),
		})

		//---

		last = ns.Zones[name]
	}

}
