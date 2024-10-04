package behaviour

import (
	"github.com/nsmithuk/naughty-nameserver/behaviour/invalid_negative"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

func GeBehaviours() []naughty.BehaviourFactory {
	return []naughty.BehaviourFactory{
		//new(valid_positive.AlgorithmCombinations),
		//new(invalid_positive.MissingNSECRecordForWildcard),
		//new(valid_negative.SingleNXDomainNsecResponse),
		//new(valid_negative.DoubleNXDomainNsecResponse),
		//new(valid_negative.NODataNsecResponse),
		new(invalid_negative.InvalidDSNsecRecordDeligation),
		new(invalid_negative.InvalidDSNsec3RecordDeligation),
		new(invalid_negative.NoOptoutDSNsec3RecordDeligation),
	}
}
