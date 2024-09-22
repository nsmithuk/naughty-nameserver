package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/naughty-nameserver/behaviour"
	"github.com/nsmithuk/naughty-nameserver/naughty"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

/*
This starts a basic Naughty DNS Server on port 53.
*/

var nameserver *naughty.Nameserver

func init() {
	naughty.Info = func(s string) {
		fmt.Print(s)
	}
	naughty.Debug = func(s string) {
		fmt.Print(s)
	}
	naughty.Warn = func(s string) {
		fmt.Print(s)
	}
	naughty.Query = func(s string) {
		fmt.Print(s)
	}
}

func main() {
	domain := dns.Fqdn("naughty.qazz.uk.")
	ns1 := "13.40.162.160"
	ns2 := "13.40.162.160"

	nameserver = naughty.NewNameserver(domain, []string{ns1, ns2})

	err := nameserver.AddBehaviours(behaviour.GetAllBehaviours())
	if err != nil {
		log.Fatal(err)
	}

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
	var a net.IP
	var port string

	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		port = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		port = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
	}

	if a != nil {
		log.Printf("Request from %s. %s\n", a.String(), port)
	}
	log.Printf("%s\n", r.String())

	//---

	msg, err := nameserver.Exchange(r)
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

	log.Printf("%s\n", msg.String())

	// Send the response
	err = w.WriteMsg(msg)
	if err != nil {
		log.Printf("Failed to write response: %v\n", err)
	}
}
