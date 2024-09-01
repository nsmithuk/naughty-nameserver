# Naughty Nameserver

Naughty Nameserver is a tool designed to facilitate the testing of DNSSEC (Domain Name System Security Extensions) 
by providing a simple method for generating DNS responses with deterministic outcomes. It serves multiple DNS 
zones, each configured to return either valid or invalid responses, depending on the testing scenario.

Originally intended as a mock for unit testing Go-based DNSSEC validators, Naughty Nameserver has since become 
widely used as a server that responds to actual DNS lookups. This makes it a versatile tool for developers and 
testers working with DNSSEC.

### Real-Time DNS Queries
Naughty Nameserver can be used as a live DNS server, responding to actual DNS queries. This makes it a 
powerful tool for developers and network administrators needing a reliable resource for DNSSEC validation testing.
A hosted version of this is running on the domain `naughty-nameserver.com`.

### Unit Testing in Go
Naughty Nameserver can be integrated into Go-based DNSSEC validator unit tests, 
especially when using [miekg/dns](https://github.com/miekg). It provides a mock of the DNS hierarchy,
including the root zone, allowing you to test full trust chains using a mocked trust anchors.

> [!CAUTION]
> Naughty Nameserver is not intended for use as a general-purpose nameserver. 
> It is intentionally designed with security limitations. Critical private keys are deliberately 
> included within the codebase, making them publicly accessible. This approach facilitates deterministic 
> testing (where needed) but exposes the server to vulnerabilities such as cache poisoning and other attack vectors that 
> DNSSEC typically protects against. Use this server only in controlled testing scenarios.

When a specific key algorithm is not mention the default of `ECDSA P-256 SHA256` is used.

# Usage

## Invalid Endpoints

### DS miss-match with the CSK used to sign the zone's records
This zone returns two CSK DNSKEYs. One signs all the records, and the other aligns with the zone's DS record.
This means that there is no trust chain as although the DS record maps to a returned key, that key was not
used to sign any of the record sets.
```text
test.missmatch-ds.naughty-nameserver.com
```

### The DS record in the parent doesn't match any key
```text
test.incorrect-ds.naughty-nameserver.com
```

### No DS records are returned from the parent
```text
test.missing-ds.naughty-nameserver.com
```

### DS record returned is for ZSK, not the KSK
A KSK was used to sign the DNSKEY records, but the DS record set is for the ZSK used for non-DNSKEY records.
```text
test.zsk-ds.naughty-nameserver.com
```

### RRSig Signature invalid with the wrong message
The returned RRSig is generated using a different A RR than what is returned in the answer.
```text
test.rrsig-signature-invalid.naughty-nameserver.com
```

### RRSing invalid as inception is in the future
The inception time is set one hour into the future.
```text
test.rrsig-inception-invalid.naughty-nameserver.com
```

### RRSing invalid as expiration is in the past
The expiration time is set one hour into the past.
```text
test.rrsig-expiration-invalid.naughty-nameserver.com
```

## Valid Endpoints

### CSK Signed with 1024 RSA / SHA1
```text
test.rsa-1024-sha1.naughty-nameserver.com
```

### CSK Signed with 2048 RSA / SHA256
```text
test.rsa-2048-sha256.naughty-nameserver.com
```

### CSK Signed with 4096 RSA / SHA256
```text
test.rsa-4096-sha512.naughty-nameserver.com
```

### CSK Signed with ECDSA P-256 / SHA256
```text
test.ecdsa-p256-sha256.naughty-nameserver.com
```

### CSK Signed with ECDSA P-384 / SHA384
```text
test.ecdsa-p384-sha384.naughty-nameserver.com
```

### CSK Signed with ed25519
```text
test.ed25519.naughty-nameserver.com
```

### Signed with two ZSKs, then one KSK.
```text
test.two-valid-zsks.naughty-nameserver.com
```

### Signed only using a ZSK (flags = 256)
```text
test.zsk-only.naughty-nameserver.com
```

### Many DS records are returned from the parent, one being valid
```text
test.multiple-ds.naughty-nameserver.com
```

### Many (7) ed25519 CSKs with the exact same Flags, Protocol, Algorithm and KeyTag
In this instance a validator should [try all keys](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1) to 
determine which is the correct one.
(Hint - it's the middle one :-)
```text
test.clashing-keys.naughty-nameserver.com
```

### Two RRSigs are returned, but only one is valid
```text
test.one-valid-one-invalid-rrsig.naughty-nameserver.com
```

# Licence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
