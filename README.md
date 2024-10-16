# Naughty Nameserver

Naughty Nameserver is a tool designed to facilitate the testing of DNSSEC (Domain Name System Security Extensions) 
by providing a simple method for generating DNS responses with deterministic outcomes. It serves multiple DNS 
zones, each configured to return either valid or invalid responses, depending on the testing scenario.

Originally intended as a mock for unit testing Go-based DNSSEC validators, Naughty Nameserver morphed into a server that responds to actual DNS lookups.
This makes it a versatile tool for developers and testers working with DNSSEC.

## Features

- **Real-Time DNS Queries**: Naughty Nameserver can be used as a live DNS server, responding to actual DNS queries. This makes it a powerful tool for developers and network administrators needing a reliable resource for DNSSEC validation testing. A hosted version is running on the domain `naughty-nameserver.com`.
- **Unit Testing in Go**: Naughty Nameserver can be integrated into Go-based DNSSEC validator unit tests, especially when using [miekg/dns](https://github.com/miekg/dns). It provides a mock of the DNS hierarchy, including the root zone, allowing you to test full trust chains using a mocked trust anchor.



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
```shell
dig @1.1.1.1 test.naughty-nameserver.com. +dnssec
````
```text
; <<>> DiG 9.10.6 <<>> @1.1.1.1 test.naughty-nameserver.com. +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15270
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;test.naughty-nameserver.com.	IN	A

;; ANSWER SECTION:
test.naughty-nameserver.com. 60	IN	A	192.0.2.53
test.naughty-nameserver.com. 60	IN	RRSIG	A 13 3 300 20241017061753 20241015061753 32442 naughty-nameserver.com. c94CbLyb0Yld9ozK5J3pjjfEuGHyuBg0dZqTXOg9piZeos2pnIbV6+2B Fn86fXe+grNywgv3pMVDx6pAbsCd+g==

;; Query time: 49 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; MSG SIZE  rcvd: 190
```

An example *invalid* response should look something like:
```shell
dig @1.1.1.1 test.invalid-signature-message.naughty-nameserver.com. +dnssec
```
```text
; <<>> DiG 9.10.6 <<>> @1.1.1.1 test.invalid-signature-message.naughty-nameserver.com. +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 18047
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
; OPT=15: 00 06 66 61 69 6c 65 64 20 74 6f 20 76 65 72 69 66 79 20 74 65 73 74 2e 69 6e 76 61 6c 69 64 2d 73 69 67 6e 61 74 75 72 65 2d 6d 65 73 73 61 67 65 2e 6e 61 75 67 68 74 79 2d 6e 61 6d 65 73 65 72 76 65 72 2e 63 6f 6d 2e 20 41 3a 20 75 73 69 6e 67 20 44 4e 53 4b 45 59 20 69 64 73 20 3d 20 5b 34 36 30 33 30 5d ("..failed to verify test.invalid-signature-message.naughty-nameserver.com. A: using DNSKEY ids = [46030]")
;; QUESTION SECTION:
;test.invalid-signature-message.naughty-nameserver.com. IN A

;; Query time: 50 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; MSG SIZE  rcvd: 189
```

## Testing Scenarios

When a specific key algorithm is not mentioned below, the default of `ECDSA P-256 SHA256` is used.

### Valid Positive Scenarios

These scenarios describe conditions where a DNSSEC validator should validate the response as secure:

1. **VP-1**: A response signed with a 1024-bit RSA key using SHA-1 should be considered secure.  
   Domain: `test.rsa-1024-sha1.naughty-nameserver.com.`  
   [RFC 6944, Section 2.3](https://datatracker.ietf.org/doc/html/rfc6944#section-2.3)

2. **VP-2**: A response signed with a 2048-bit RSA key using SHA-256 should be considered secure.  
   Domain: `test.rsa-2048-sha256.naughty-nameserver.com.`  
   [RFC 6944, Section 2.3](https://datatracker.ietf.org/doc/html/rfc6944#section-2.3)

3. **VP-3**: A response signed with a 4096-bit RSA key using SHA-512 should be considered secure.  
   Domain: `test.rsa-4096-sha512.naughty-nameserver.com.`  
   [RFC 6944, Section 2.3](https://datatracker.ietf.org/doc/html/rfc6944#section-2.3)

4. **VP-4**: A response signed with an ECDSA P-256 key using SHA-256 should be considered secure.  
   Domain: `test.ecdsa-p256-sha256.naughty-nameserver.com.`  
   [RFC 6944, Section 2.3](https://datatracker.ietf.org/doc/html/rfc6944#section-2.3)

5. **VP-5**: A response signed with an ECDSA P-384 key using SHA-384 should be considered secure.  
   Domain: `test.ecdsa-p384-sha384.naughty-nameserver.com.`  
   [RFC 6944, Section 2.3](https://datatracker.ietf.org/doc/html/rfc6944#section-2.3)

6. **VP-6**: A response signed with an Ed25519 key should be considered secure.  
   Domain: `test.ed25519.naughty-nameserver.com.`  
   [RFC 6944, Section 2.3](https://datatracker.ietf.org/doc/html/rfc6944#section-2.3)

7. **VP-7**: A response synthesized from a wildcard, including the expected NSEC record, should be considered secure.  
   Domain: `test.wildcard-with-nsec.naughty-nameserver.com.`  
   [RFC 4035, Section 5.3.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.4)

8. **VP-8**: A response synthesized from a wildcard, including the expected NSEC3 record, should be considered secure.  
   Domain: `test.wildcard-with-nsec3.naughty-nameserver.com.`  
   [RFC 4035, Section 5.3.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.4)

9. **VP-9**: A response signed with a DNSKEY that has a flag set to 256 should be considered secure.  
   Domain: `test.key-flag-256.naughty-nameserver.com.`  
   [RFC 4034, Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1)

10. **VP-10**: A response signed with a DNSKEY that has a flag set to 257 should be considered secure.  
    Domain: `test.key-flag-257.naughty-nameserver.com.`  
    [RFC 4034, Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1)

11. **VP-11**: A response associated with multiple DNSKEYs, where at least one key is valid and signs the RRSet, should be considered secure.  
    Domain: `test.clashing-keys.naughty-nameserver.com.`  
    [RFC 4035, Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1)

12. **VP-12**: A response with multiple DS records from a parent zone, where at least one DS record is valid, should be considered secure.  
    Domain: `test.multiple-ds.naughty-nameserver.com.`  
    [RFC 4035, Section 2.4](https://datatracker.ietf.org/doc/html/rfc4035#section-2.4)

13. **VP-13**: A response with no DS record at a delegation point, where an NSEC3 record with the opt-out flag covers it, should be valid (but insecure).  
    Domain: `test.deligation-optout-nsec3.naughty-nameserver.com.`  
    [RFC 5155, Section 6](https://datatracker.ietf.org/doc/html/rfc5155#section-6)

### Invalid Positive Scenarios

These scenarios describe conditions where a DNSSEC validator should mark the response as bogus:

1. **IP-1**: A synthesized response from a wildcard with an RRSIG label count mismatch and missing NSEC(3) records should be considered bogus.  
   Domain: `test.nsec-missing-with-wildcard.naughty-nameserver.com.`  
   [RFC 4035, Section 5.3.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.4), [RFC 5155, Section 8.7](https://datatracker.ietf.org/doc/html/rfc5155#section-8.7)

2. **IP-2**: A response signed with a DNSKEY where bit 7 of the flags is 0 should be considered bogus.  
   Domain: `test.invalid-key-flag.naughty-nameserver.com.`  
   [RFC 4034, Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1)

3. **IP-3**: A response signed by a ZSK, where the DS record only points to the ZSK and not the KSK, should be considered bogus.  
   Domain: `test.ds-key-missmatch.naughty-nameserver.com.`  
   [RFC 4035, Section 5.2](https://datatracker.ietf.org/doc/html/rfc4035#section-5.2)

4. **IP-4**: A response where the RRSet has changed since it was signed by the RRSIG should be considered bogus.  
   Domain: `test.invalid-signature-message.naughty-nameserver.com.`  
   [RFC 4035, Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1)

5. **IP-5**: A response with an RRSIG inception date set in the future should be considered bogus.  
   Domain: `test.inception-in-future.naughty-nameserver.com.`  
   [RFC 4035, Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1)

6. **IP-6**: A response with an RRSIG expiration date set in the past should be considered bogus.  
   Domain: `test.expiration-in-past.naughty-nameserver.com.`  
   [RFC 4035, Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1)

7. **IP-7**: A response where one or more RRTypes lack a valid RRSIG should be considered bogus.  
   [RFC 4035, Section 2.2](https://datatracker.ietf.org/doc/html/rfc4035#section-2.2), [RFC 4035, Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1)

### Valid Negative Scenarios

These scenarios describe conditions where a DNSSEC validator should validate the response as secure despite indicating no data (NODATA) or non-existence (NXDOMAIN):

1. **VN-1**: An NXDOMAIN response with a single NSEC record covering both the QName and wildcard should be considered valid.  
   Domain: `test.single-nsec-record.naughty-nameserver.com.`  
   [RFC 4035, Section 5.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.4)

2. **VN-2**: An NXDOMAIN response with two NSEC records, one covering the QName and one for the wildcard, should be considered valid.  
   Domain: `test.two-nsec-records.naughty-nameserver.com.`  
   [RFC 4035, Section 5.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.4)

3. **VN-3**: A NODATA response with a single NSEC record showing the QType as missing should be considered valid.  
   Domain: `test.nsec-nodata.naughty-nameserver.com.`  
   [RFC 4035, Section 5.4](https://datatracker.ietf.org/doc/html/rfc4035#section-5.4)

4. **VN-4**: An NXDOMAIN response with a single NSEC3 record covering the Closest Encloser, Next closer name, and wildcard should be considered valid.  
   Domain: `test.one-nsec3-nxdomain.naughty-nameserver.com.`  
   [RFC 5155, Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc5155#section-7.2.2)

5. **VN-5**: An NXDOMAIN response with two NSEC3 records, one for the Closest Encloser and Next closer name, and another for the wildcard, should be considered valid.  
   Domain: `test.two-a-nsec3-nxdomain.naughty-nameserver.com.`  
   [RFC 5155, Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc5155#section-7.2.2)

6. **VN-6**: An NXDOMAIN response with two NSEC3 records, one for the Closest Encloser and another for the Next closer name and wildcard, should be considered valid.  
   Domain: `test.two-b-nsec3-nxdomain.naughty-nameserver.com.`  
   [RFC 5155, Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc5155#section-7.2.2)

7. **VN-7**: An NXDOMAIN response with three NSEC3 records, one each for the Closest Encloser, Next closer name, and wildcard, should be considered valid.  
   Domain: `test.three-nsec3-nxdomain.naughty-nameserver.com.`  
   [RFC 7129, Section 5.5](https://datatracker.ietf.org/doc/html/rfc7129#section-5.5), [RFC 5155, Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc5155#section-7.2.2)

8. **VN-8**: A NODATA response with a single NSEC3 record showing the QType as missing should be considered valid.  
   Domain: `test.nsec3-nodata.naughty-nameserver.com.`  
   [RFC 5155, Section 7.2.3](https://datatracker.ietf.org/doc/html/rfc5155#section-7.2.3)

### Invalid Negative Scenarios

These scenarios describe conditions where a DNSSEC validator should mark the response as bogus due to an invalid or improperly configured negative response:

1. **IN-1**: A response missing a DS record at a delegation point where the QName matching the NSEC record has the DS bit set should be considered bogus.  
   Domain: `test.invalid-deligation-nsec3-bitmap.naughty-nameserver.com.`

2. **IN-2**: A response missing a DS record at a delegation point where the QName matching the NSEC3 record has the DS bit set should be considered bogus.  
   Domain: `test.invalid-deligation-nsec3-bitmap.naughty-nameserver.com.`  
   [RFC 5155, Section 8](https://datatracker.ietf.org/doc/html/rfc5155#section-8)

3. **IN-3**: A response missing a DS record at a delegation point where the NSEC3 record covering it does not have the opt-out flag set should be considered bogus.  
   Domain: `test.missing-deligation-optout-nsec3.naughty-nameserver.com.`  
   [RFC 5155, Section 6](https://datatracker.ietf.org/doc/html/rfc5155#section-6)

4. **IN-4**: A response with an NSEC3 record that has an unknown hash algorithm should be considered bogus, assuming no other valid records.  
   Domain: `test.nsec3-invalid-hash.naughty-nameserver.com.`  
   [RFC 5155, Section 8.1](https://datatracker.ietf.org/doc/html/rfc5155#section-8.1)

5. **IN-5**: A response with an NSEC3 record that has a flag value other than 0 or 1 should be considered bogus, assuming no other valid records.  
   Domain: `test.nsec3-invalid-flag.naughty-nameserver.com.`  
   [RFC 5155, Section 8.2](https://datatracker.ietf.org/doc/html/rfc5155#section-8.2)

6. **IN-6**: A response missing a DS record at a delegation point, without a valid denial of existence, should be considered bogus.  
   Domain: `test.deligation-no-ds.naughty-nameserver.com.`  
   [RFC 5155, Section 6](https://datatracker.ietf.org/doc/html/rfc5155#section-6)


### Experimental Scenarios - Post Quantum Cryptography

These scenarios are highly experimental and involve the use of Post Quantum Cryptography (PQC) with the ML-DSA (Module-Lattice Digital Signature Algorithm) for signing. Since PQC is not currently part of any DNSSEC RFC, these scenarios are included for testing cutting-edge cryptographic techniques.

1. **EXP-1**: A positive response signed with ML-DSA-44 should be considered secure.  
   Domain: `test.ml-dsa-44.naughty-nameserver.com.`

2. **EXP-2**: A positive response signed with ML-DSA-65 should be considered secure.  
   Domain: `test.ml-dsa-65.naughty-nameserver.com.`

3. **EXP-3**: A positive response signed with ML-DSA-87 should be considered secure.  
   Domain: `test.ml-dsa-87.naughty-nameserver.com.`

### Thoughts on the Impact of Post Quantum Cryptography (PQC)

The introduction of Post Quantum Cryptography (PQC) to DNSSEC could bring significant changes, particularly concerning how DNS messages are transmitted. One of the main implications is the size of the signed keysets when using PQC algorithms like ML-DSA, which are substantially larger than those of current cryptographic standards.

- For context, a signed keyset using ECDSA P-256 is around **400 bytes**.
- A signed keyset using RSA 2048 is approximately **800 bytes**.
- In comparison, a signed keyset using the smallest level (44) of ML-DSA is about **4,000 bytes**.
- The NSCS recommended level (65) of ML-DSA results in a signed keyset of around **5,500 bytes**.

Given these sizes, it's clear that some DNS messages may no longer be suitable for transmission over UDP, particularly during DNSKEY lookups. Traditionally, DNS uses UDP for its efficiency, but there is a tendency to avoid UDP for any response over **4,096 bytes**. Larger responses risk fragmentation, which can lead to packet loss and other issues.

As a result, to accommodate the increased size of PQC-signed keysets, we may need to rely more heavily on **TCP** for DNS transactions. While this shift could have performance implications, especially in terms of latency and connection overhead, it is a necessary adaptation to ensure DNSSEC remains secure against future quantum attacks. Thus, the integration of PQC may herald a new era where the DNS ecosystem evolves to prioritize reliability and security over speed, marking a notable shift in its design philosophy.

#### See the example from above
```shell
dig @ns1.naughty-nameserver.com ecdsa-p256-sha256.naughty-nameserver.com. DNSKEY +dnssec
```
```shell
dig @ns1.naughty-nameserver.com rsa-2048-sha256.naughty-nameserver.com. DNSKEY +dnssec
```
```shell
dig @ns1.naughty-nameserver.com ml-dsa-44.naughty-nameserver.com. DNSKEY +dnssec
```
```shell
dig @ns1.naughty-nameserver.com ml-dsa-65.naughty-nameserver.com. DNSKEY +dnssec
```
   
# Licence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
