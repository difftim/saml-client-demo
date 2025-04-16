module samlclient

go 1.19

require github.com/crewjam/saml v0.4.8

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/russellhaering/goxmldsig v1.2.0 // indirect
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed // indirect
)

replace (
	github.com/crewjam/saml => github.com/crewjam/saml v0.4.0
	github.com/russellhaering/goxmldsig => github.com/russellhaering/goxmldsig v1.1.0
)
