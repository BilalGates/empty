# iOS cryptographic dependency record

The `SpaceShared` target uses two narrowly scoped, immutable SwiftPM revisions. Do not
move either pin without the crypto change gate, regenerated cross-platform vectors,
dependency diff review, and macOS/device evidence.

## XChaCha20-Poly1305-IETF

- Package: `https://github.com/jedisct1/swift-sodium.git`
- Release: `0.11.0`
- Annotated tag object: `df17ff800f85491b2cdb5c9d0426dacb40761ad2`
- Pinned commit: `cfd195c76882aa9b997560ca7cb95d72fbf5db00`
- Bundled libsodium: `1.0.22`; upstream revision declared by the package:
  `8cda270b3b18ca103c57085752cece1ebbf5abee`
- iOS arm64/arm64e static-library SHA-256:
  `d678dc76dbc6e34d30954f3644622aae8cbbacf3da03226416e7684196e65393`
- iOS simulator arm64/arm64e/x86_64 static-library SHA-256:
  `b59ff5ecd5d00674d1dd52c8155b613ebbcaf630cf6a7b29e0710dff7dd38e17`

The release tag contains a signature made by fingerprint
`0C7983A8FD9A104C623172CB62F25B592B6F76DA`. GitHub reports it verified, but the
local Windows review machine did not have the maintainer public key, so local GPG
trust verification remains a macOS/CI supply-chain gate. The project pins the commit,
not the mutable tag name.

## Argon2id

- Package: `https://github.com/P-H-C/phc-winner-argon2.git`
- Pinned commit: `f57e61e19229e23c4445b85494dbf7c07de721cb`
- Product/module: `argon2`
- License: CC0-1.0 or Apache-2.0

This is the Password Hashing Competition reference C implementation. It is used instead
of libsodium's password-hashing facade because that facade does not expose Argon2 lanes;
`space.vault/1` requires `p=4`. The Swift adapter calls `argon2id_hash_raw` with exactly
`m=65536 KiB`, `t=3`, `p=4`, a 16-byte salt, and 32-byte output. The AutoFill extension
must never run Argon2 or lower those values; master-password derivation belongs to the
host app.

## Re-verification

From clean temporary clones, verify commits and compare the XCFramework slices before
allowing Xcode to resolve packages:

```sh
git ls-remote https://github.com/jedisct1/swift-sodium.git refs/tags/0.11.0
git clone --depth 1 --branch 0.11.0 https://github.com/jedisct1/swift-sodium.git
git -C swift-sodium rev-parse HEAD
git -C swift-sodium tag -v 0.11.0
shasum -a 256 swift-sodium/Clibsodium.xcframework/ios-arm64_arm64e/libsodium.a
shasum -a 256 swift-sodium/Clibsodium.xcframework/ios-arm64_arm64e_x86_64-simulator/libsodium.a
git ls-remote https://github.com/P-H-C/phc-winner-argon2.git HEAD
```

An Xcode build must resolve exactly the two revisions in `project.yml`. Retain the
generated `Package.resolved` in CI evidence and fail if it differs.
