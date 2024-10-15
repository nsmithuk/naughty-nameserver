package behaviour

import (
	"github.com/nsmithuk/naughty-nameserver/behaviour/invalid_negative"
	"github.com/nsmithuk/naughty-nameserver/behaviour/invalid_positive"
	"github.com/nsmithuk/naughty-nameserver/behaviour/valid_negative"
	"github.com/nsmithuk/naughty-nameserver/behaviour/valid_positive"
	"github.com/nsmithuk/naughty-nameserver/naughty"
)

func GeBehaviours() []naughty.BehaviourFactory {
	return []naughty.BehaviourFactory{
		// Valid Positive
		new(valid_positive.AlgorithmCombinations),
		new(valid_positive.NSECRecordForWildcard),
		new(valid_positive.NSEC3RecordForWildcard),
		new(valid_positive.KeyFlag256),
		new(valid_positive.KeyFlag257),
		new(valid_positive.MultipleClashingKeys),
		new(valid_positive.MultipleDsRecords),
		new(valid_positive.OptoutDSNsec3RecordDeligation),
		new(valid_positive.AlgorithmCombinationsPqc),

		// Invalid Positive
		new(invalid_positive.MissingNSECRecordForWildcard),
		new(invalid_positive.InvalidKeyFlag),
		new(invalid_positive.DsKeyMissmatch),
		new(invalid_positive.RRSetDoesNotMatchRRSig),
		new(invalid_positive.InceptionInFuture),
		new(invalid_positive.ExpirationInPast),
		new(invalid_positive.MissingRRSig),

		// Valid Negative
		new(valid_negative.SingleNXDomainNsecResponse),
		new(valid_negative.DoubleNXDomainNsecResponse),
		new(valid_negative.NODataNsecResponse),
		new(valid_negative.SingleNXDomainNsec3Response),
		//new(valid_negative.DoubleCeAndNcnThenWcNXDomainNsec3Response),
		//new(valid_negative.DoubleCeThenNcnAndWcNXDomainNsec3Response),
		//new(valid_negative.DoubleCeAndWcThenNcnNXDomainNsec3Response),
		new(valid_negative.TripleNXDomainNsec3Response),
		new(valid_negative.NODataNsec3Response),

		// Invalid Negative
		new(invalid_negative.InvalidDSNsecRecordDeligation),
		new(invalid_negative.InvalidDSNsec3RecordDeligation),
		new(invalid_negative.NoOptoutDSNsec3RecordDeligation),
		new(invalid_negative.InvalidNsec3Hash),
		new(invalid_negative.InvalidNsec3Flag),
		new(invalid_negative.MissingDSRecords),
	}
}
