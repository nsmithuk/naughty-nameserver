package naughty

import (
	"github.com/miekg/dns"
)

type Signer interface {
	Keys() []*dns.DNSKEY
	Sign(*dns.Msg) (*dns.Msg, error)
	DelegatedSingers() []*dns.DS
}
