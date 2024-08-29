package naughty

import "github.com/miekg/dns"

type Mutator interface {
	PreSigning(*dns.Msg) *dns.Msg
	PostSigning(*dns.Msg) *dns.Msg
}

type DefaultMutator struct{}

func (m *DefaultMutator) PreSigning(msg *dns.Msg) *dns.Msg {
	return msg
}

func (m *DefaultMutator) PostSigning(msg *dns.Msg) *dns.Msg {
	return msg
}
