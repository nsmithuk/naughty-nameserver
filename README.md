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

# Usage

All test domains are prefixed with the label `test.`. They are all designed to return a single A record
with the IP address `192.0.2.53`. In the case of the lookup being performed via a DNSSEC aware resolver, then
this A record should _not_ be returned for domains that are designed to return an invalid response.

An example *valid* response will look something like:
```text
dig @1.1.1.1 test.naughty-nameserver.com. +dnssec

; <<>> DiG 9.10.6 <<>> @1.1.1.1 test.naughty-nameserver.com. +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54057
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;test.naughty-nameserver.com.	IN	A

;; ANSWER SECTION:
test.naughty-nameserver.com. 60	IN	A	192.0.2.53
test.naughty-nameserver.com. 60	IN	RRSIG	A 13 3 300 20240902140751 20240831140751 25649 naughty-nameserver.com. AToTP/lo9uP/Yj+can2BwBYapCnvZrpqTzLtc1FtRg6gDExJa2xbXrtP 0yVQK72KAbZ7qVUzwgz9xS6+yGKTGQ==

;; Query time: 16 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Sun Sep 01 15:07:51 BST 2024
;; MSG SIZE  rcvd: 190
```

An example *invalid* response will look something like:
```text
dig @1.1.1.1 test.rrsig-signature-invalid.naughty-nameserver.com. +dnssec

; <<>> DiG 9.10.6 <<>> @1.1.1.1 test.rrsig-signature-invalid.naughty-nameserver.com. +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 52689
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
; OPT=15: 00 06 66 61 69 6c 65 64 20 74 6f 20 76 65 72 69 66 79 20 74 65 73 74 2e 72 72 73 69 67 2d 73 69 67 6e 61 74 75 72 65 2d 69 6e 76 61 6c 69 64 2e 6e 61 75 67 68 74 79 2d 6e 61 6d 65 73 65 72 76 65 72 2e 63 6f 6d 2e 20 41 3a 20 75 73 69 6e 67 20 44 4e 53 4b 45 59 20 69 64 73 20 3d 20 5b 33 32 32 38 5d ("..failed to verify test.rrsig-signature-invalid.naughty-nameserver.com. A: using DNSKEY ids = [3228]")
;; QUESTION SECTION:
;test.rrsig-signature-invalid.naughty-nameserver.com. IN	A

;; Query time: 53 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Sun Sep 01 15:08:48 BST 2024
;; MSG SIZE  rcvd: 184
```

Note - when a specific key algorithm is not mentioned below, the default of `ECDSA P-256 SHA256` is used.

## Invalid Domains

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

## Valid Domains

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

### Resolved using a Wildcard
Includes the expected NSEC records
```text
test.wildcard.naughty-nameserver.com
```

### Chained CNAMEs with Wildcards
Uses 3 chained CNAME records, 2 of them wildcards. And 1 wildcard A record. Includes all expected NSEC records.
```text
test.cname-chain.naughty-nameserver.com
```

# Licence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
