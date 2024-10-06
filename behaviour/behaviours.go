package behaviour

import (
	"github.com/nsmithuk/naughty-nameserver/behaviour/invalid_positive"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

func GeBehaviours() []naughty.BehaviourFactory {
	return []naughty.BehaviourFactory{
		// Valid Positive
		//new(valid_positive.AlgorithmCombinations),
		//new(valid_positive.NSECRecordForWildcard),
		//new(valid_positive.NSEC3RecordForWildcard),
		//new(valid_positive.KeyFlag256),
		//new(valid_positive.KeyFlag257),
		//new(valid_positive.MultipleClashingKeys),
		//new(valid_positive.MultipleDsRecords),
		//new(valid_positive.OptoutDSNsec3RecordDeligation),

		// Invalid Positive
		//new(invalid_positive.MissingNSECRecordForWildcard),
		//new(invalid_positive.InvalidKeyFlag),
		//new(invalid_positive.DsKeyMissmatch),
		//new(invalid_positive.RRSetDoesNotMatchRRSig),
		//new(invalid_positive.InceptionInFuture),
		//new(invalid_positive.ExpirationInPast),
		new(invalid_positive.MissingRRSig),

		//new(valid_negative.SingleNXDomainNsecResponse),
		//new(valid_negative.DoubleNXDomainNsecResponse),
		//new(valid_negative.NODataNsecResponse),
		//new(invalid_negative.InvalidDSNsecRecordDeligation),
		//new(invalid_negative.InvalidDSNsec3RecordDeligation),
		//new(invalid_negative.NoOptoutDSNsec3RecordDeligation),
	}
}
