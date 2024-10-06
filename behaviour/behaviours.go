package behaviour

import (
	"github.com/nsmithuk/naughty-nameserver/behaviour/valid_positive"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

func GeBehaviours() []naughty.BehaviourFactory {
	return []naughty.BehaviourFactory{
		//new(valid_positive.AlgorithmCombinations),
		//new(valid_positive.NSECRecordForWildcard),
		//new(valid_positive.NSEC3RecordForWildcard),
		new(valid_positive.KeyFlag256),
		new(valid_positive.KeyFlag257),

		//new(invalid_positive.MissingNSECRecordForWildcard),
		//new(valid_negative.SingleNXDomainNsecResponse),
		//new(valid_negative.DoubleNXDomainNsecResponse),
		//new(valid_negative.NODataNsecResponse),
		//new(invalid_negative.InvalidDSNsecRecordDeligation),
		//new(invalid_negative.InvalidDSNsec3RecordDeligation),
		//new(invalid_negative.NoOptoutDSNsec3RecordDeligation),
	}
}
