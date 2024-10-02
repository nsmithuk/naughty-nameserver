package behaviour

import (
	"github.com/nsmithuk/naughty-nameserver/behaviour/invalid_positive"
	"github.com/nsmithuk/naughty-nameserver/behaviour/valid_negative"
	"github.com/nsmithuk/naughty-nameserver/behaviour/valid_positive"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

func GeBehaviours() []naughty.BehaviourFactory {
	return []naughty.BehaviourFactory{
		new(valid_positive.AlgorithmCombinations),
		new(invalid_positive.MissingNSECRecordForWildcard),
		new(valid_negative.SingleNXDomainNsecResponse),
		new(valid_negative.DoubleNXDomainNsecResponse),
		new(valid_negative.NODataNsecResponse),
	}
}
