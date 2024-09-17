package behaviour

import "github.com/nsmithuk/naughty-nameserver/naughty"

const (
	logFmtValid   = "valid:\t%s\n"
	logFmtInvalid = "invalid:\t%s\n"
)

func GetAllBehaviours() map[string]naughty.BehaviourFactory {
	return map[string]naughty.BehaviourFactory{
		"all-valid":             new(AllValidAlgorithms),
		"invalid-rrsig":         new(InvalidRRSigSignature),
		"zsk-only":              new(ZskOnly),
		"two-valid-zsks":        new(TwoValidZsks),
		"invalid-rrsig-dates":   new(InvalidRRSigDates),
		"clashing-keys":         new(ClashingKeys),
		"incorrect-ds":          new(IncorrectDS),
		"missing-ds":            new(MissingDS),
		"multiple-ds":           new(MultipleDS),
		"missmatch-ds":          new(MissmatchDS),
		"zsk-ds":                new(ZskDS),
		"one-valid-one-invalid": new(ValidInvalidRRSig),
		"wildcard-valid":        new(WildcardValid),
		"cname-chain":           new(CnameChain),
		"simple-cname":          new(SimpleCname),
	}
}
