# polyval

[![Go Reference](https://pkg.go.dev/badge/github.com/ericlagergren/polyval.svg)](https://pkg.go.dev/github.com/ericlagergren/polyval)

This module implements POLYVAL per [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452).

The universal hash function POLYVAL is the byte-wise reverse of
GHASH.

## Performance

The x86-64 and ARMv8 assembly backends run at about 0.25 cycles
per byte. The x86-64 implementation requires SSE2 and PCLMULQDQ
instructions. The ARMv8 implementation requires NEON and PMULL.

The default Go implementation will be selected if the CPU does
not support either assembly implementation. (This implementation
can also be selected with the `purego` build tag.) It is much 
slower at around 9 cycles per byte.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
