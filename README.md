# naughty-nameserver

When a specific key algorithm is not mention the default of `ECDSA P-256 / SHA256` is used.

## Invalid Endpoints

### The DS record in the parent is for the ZSK, not the KSK key
Is this different to the above?
I think so as we'd catch a missing KSK at the sig checking stage.
We wouldn't catch the DS issue until a later stage.
But also a DS can point at a ZSK. Maybe the point it that it poitns as a ZSK that wasn't used for signing?

### The DS record in the parent doesn't match any key


### RRSig Signature invalid with the wrong message
The returned RRSig is generated using a different A RR than what is returned in the answer.
```text
test.rrsig-signature-invalid.naughty-nameserver.com
```

### RRSing Signature invalid with the wrong key
The returned RRSig has been signed with a different key to that specified in the key tag.
i.e. a key is returned with a matching tag, but the RRSig wasn't actually signed with the key.


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

### Two RRSigs are returned, but only one is valid


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

### Signed with two ZSKs, then one ZSK.
```text
test.two-valid-zsks.naughty-nameserver.com
```

### Signed only using a ZSK
```text
test.zsk-only.naughty-nameserver.com
```

### Seven ed25519 CSKs with the exact same Flags, Protocol, Algorithm and Tag
In this instance a validator should [try all keys](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1) to determine which is the correct one.
(Hint - it's the middle one :-)

### DS hashed using SHA1
### DS hashed using SHA256
### DS hashed using SHA384
### DS hashed using SHA512
