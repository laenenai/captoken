# captoken

A bearer credential that can only ever be narrowed: minting, attenuation, typed caveats, offline verification, chain revocation, single-use nonces.

**Not in scope:** Any knowledge of principals, groups or policy. Subjects are opaque ids. It cannot answer "may they?" — only "is this credential valid, and what does it permit?"

See [CHARTER.md](CHARTER.md) for the boundary and how it is enforced, and
`api.txt` for the public surface.
