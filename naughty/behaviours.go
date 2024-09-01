package naughty

type BehaviourFactory interface {
	Setup(*Nameserver) error
}
