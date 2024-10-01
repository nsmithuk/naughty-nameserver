package naughty

type OldBehaviourFactory interface {
	Setup(*Nameserver) error
}

type BehaviourFactory interface {
	Setup(*Nameserver) []*Zone
}
