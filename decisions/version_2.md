# architectural decisions for v2

There are a few problems aside from the normal amount of cruft that naturally accumulates in a software project:

- The private key is half the size of the public key
- Signing key is derived from the encryption key. That sounds like a bad idea.
- Key material should be an opaque block of bytes, just like Peer.

Peers should have something more robust than Nickname() for uniqueness.

A version field should be included in the configs, for breaking changes.