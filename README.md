
# SFrame

This repository contains an implementation of [the draft SFrame
standard](https://datatracker.ietf.org/doc/html/draft-omara-sframe) for
end-to-end media encryption.  Since the spec is still in progress, the
implementation here doesn't match exactly.  For example:

* We do not derive key/salt from the master key.  The key is used directly, and
  the nonce is formed directly from the counter, with no salt.

* We use AES-GCM instead of the AES-CTR + HMAC construction in the
  specification.

* We include the SFrame header as AAD in the encryption

Ideally, these differences will resolve as the specification and this
implementaiton evolve together.

## Building and Running Tests

A convenience Makefile is included to avoid the need to remember a bunch of
CMake parameters.

```
> make        # Configures all targets and builds the library
> make test   # Builds and runs tests
```

## Prerequisites

You need openssl 1.1 or greater installed, C++ compiler, make, and cmake




