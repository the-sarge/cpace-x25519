# Security Policy

Report security issues privately before opening a public issue. Email
`josh@joshuasargent.com`, or use GitHub private vulnerability reporting for
`the-sarge/cpace` if it is enabled.

This repository is an unaudited implementation of an active Internet-Draft:
`draft-irtf-cfrg-cpace-21`, published April 23, 2026. Do not describe it as
production-ready until independent cryptographic review is complete.

Supported scope for the initial implementation:

- `CPACE-RISTR255-SHA512`
- initiator-responder mode
- mandatory explicit key confirmation

Unsupported scope:

- symmetric mode
- draft revisions other than draft-21
- ciphersuites other than Ristretto255 with SHA-512
