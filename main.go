package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"naughty-nameserver/behaviour"
	"naughty-nameserver/naughty"
	"os"
	"os/signal"
	"syscall"
)

var nameserver *naughty.Nameserver

type BehaviourFactory interface {
	Setup(*naughty.Nameserver) error
}

func main() {
	domain := dns.Fqdn("naughty-nameserver.com.")
	ns1 := "13.42.38.192"
	ns2 := "13.42.38.192"

	nameserver = naughty.NewNameserver(domain, []string{ns1, ns2})

	behaviours := map[string]BehaviourFactory{
		"invalid-rrsig": &behaviour.InvalidRRSig{},
	}

	for _, b := range behaviours {
		if err := b.Setup(nameserver); err != nil {
			log.Fatal(err)
		}
	}

	ns := nameserver
	fmt.Println(ns.RootDelegatedSingers()[0].String())
	fmt.Println(ns.BaseDelegatedSingers()[0].String())

	go startDNSServer("udp", ":53")
	go startDNSServer("tcp", ":53")

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}

// Start DNS server on the specified network and address
func startDNSServer(network, address string) {
	server := &dns.Server{Addr: address, Net: network}

	dns.HandleFunc(".", handleDNSRequest)

	log.Printf("Starting %s DNS server on %s\n", network, address)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start %s DNS server: %v\n", network, err)
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg, err := nameserver.Query(r)
	if err != nil {
		log.Printf("Failed to generate response: %v\n", err)
	}

	if msg == nil {
		// Report an error
		msg = new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = false
		msg.RecursionAvailable = false
		msg.Rcode = dns.RcodeServerFailure
	}

	// Send the response
	err = w.WriteMsg(msg)
	if err != nil {
		log.Printf("Failed to write response: %v\n", err)
	}
}
