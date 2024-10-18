module github.com/nsmithuk/naughty-nameserver

go 1.23.2

replace github.com/miekg/dns v1.1.62 => github.com/nsmithuk/dns v1.1.62-pqc

require (
	github.com/cloudflare/circl v1.5.0
	github.com/miekg/dns v1.1.62
)

require (
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/tools v0.26.0 // indirect
)
