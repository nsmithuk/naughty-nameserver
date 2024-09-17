package naughty

import "github.com/miekg/dns"

func DefaultDenyExistenceNSEC(msg *dns.Msg, store RecordStore, wildcardsUsed synthesisedResults) (*dns.Msg, error) {
	return msg, nil
}
