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
		records[i] = GluedNS{
			A: &dns.A{
				Hdr: NewHeader(host, dns.TypeA),
				A:   net.ParseIP(ip).To4(),
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

	server.BuildInitialZones()

	return server
}

func (ns *Nameserver) RootDelegatedSingers() []*dns.DS {
	return ns.RootZone.Callbacks.DelegatedSingers()
}

func (ns *Nameserver) BaseDelegatedSingers() []*dns.DS {
	return ns.BaseZone.Callbacks.DelegatedSingers()
}

func (ns *Nameserver) Query(qmsg *dns.Msg) (*dns.Msg, error) {
	name := strings.ToLower(dns.Fqdn(qmsg.Question[0].Name))

	/*
		We want to find the most specific zone for the Question.

		Break the name into labels, then loops through...
		deep.invalid.naughty-dns.com.
		invalid.naughty-dns.com.
		naughty-dns.com.
		com.
		.
	*/
	for zoneName := range IterateDomainHierarchy(name) {

		// Is there is a zone with this name...
		// Note that this map does not change once the server is setup, thus we don't need and thread-safe locking here.
		if zone, ok := ns.Zones[zoneName]; ok {
			rmsg, err := zone.Query(qmsg)

			// If one, or both, are not nil, return.
			if rmsg != nil || err != nil {
				return rmsg, err
			}

			// Else we stay in the loop as a parent may have an answer.
			// This is especially the case for DS records.
		}
	}

	// Say we can't help...
	rmsg := new(dns.Msg)
	rmsg.SetReply(qmsg)
	rmsg.Authoritative = false
	rmsg.RecursionAvailable = false
	rmsg.Rcode = dns.RcodeNameError

	return rmsg, fmt.Errorf("no response found for %s", name)
}

func (ns *Nameserver) BuildInitialZones() {
	var last *Zone
	for name := range IterateDomainHierarchy(ns.BaseZoneName) {
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
		} else if name == ns.BaseZoneName {
			ns.BaseZone = ns.Zones[name]
			fmt.Println("--------------------------------------")
			fmt.Printf("KSK Details for %s\n", name)
			for _, key := range signer.Keys() {
				fmt.Printf("Key:\t%d:\t%s\n", key.KeyTag(), key.String())
			}
			fmt.Printf("DS:\t%s\n", signer.DelegatedSingers()[0])
			fmt.Println("--------------------------------------")
		}

		ns.Zones[name].AddRecord(&dns.A{
			Hdr: NewHeader(fmt.Sprintf("test.%s", strings.TrimRight(name, ".")), dns.TypeA),
			A:   net.ParseIP("192.0.2.53"),
		})

		last = ns.Zones[name]
	}

}
