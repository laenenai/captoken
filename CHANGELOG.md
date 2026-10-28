# Changelog

All notable changes to `captoken` are recorded here. The format is
human-readable; versions follow SemVer with the pre-1.0 rule that a minor
release may break the API. See `UPGRADING.md` for migration steps.

## Unreleased

### Tooling and compatibility

- **The AST-generated API golden file is gone.** The root `api.txt`,
  `api_test.go`/`TestAPIGolden`, and `mise run api` were removed. API
  compatibility is now checked with `apidiff` against the last root tag
  (`mise run api-diff`) and with `gorelease` on a clean release
  (`mise run release-check`). `apidiff` ignores `internal/...` by default;
  internal packages are not part of the compatibility contract.
- `mise.toml` is the single source of tool versions. CI installs mise and runs
  `mise run check` instead of pinning Go, gofumpt or golangci-lint in workflow
  YAML.
- `mise run check` now includes `tidy-check`, `generate-check` (this library
  has no generators; the guard fails if one appears without a real check),
  `vuln` (`govulncheck`), `api-diff`, and the committed wire-format vector
  check.
- Added a release workflow that runs the normal gate and `gorelease` on a
  tagged commit; added this changelog and `UPGRADING.md`.
- Toolchain: Go 1.27.3, golangci-lint 2.15.0, gofumpt 0.12.0.

### API and behaviour

- **Public packages.** `domain`, `caveat`, `chain` and `reserve` moved out of
  `internal/`, so godoc and pkg.go.dev show their fields and methods. The root
  package keeps type aliases and thin forwards, so most root-package code
  continues to compile.
- **Revocation is required.** `NewVerifier` now refuses a `VerifierConfig`
  with neither `Revocations` nor an explicit `NoRevocation: true`. A nil
  revocation backend is no longer a silent skip.
- **Verifier-owned time.** `Verify` ignores `Request.Now` and always reads
  `VerifierConfig.Clock`; `VerifyAt` takes an explicit instant. `CheckAll`
  refuses a zero `Request.Now`.
- **Verified field rename.** `Verified.Resources` is now
  `Verified.TerminalResources`, making clear that it is the terminal link's
  scope and not the chain-wide intersection.
- **Holder-supplied keys and `crypto.Signer`.** `MintSpec.HolderPublicKey`
  binds a public key the holder owns; `MinterConfig.RootKey` and
  `Deriver.Derive`'s holder key accept `crypto.Signer`. Identity and
  small-order Ed25519 public keys are rejected.
- **Stricter decoder and bounds.** The verifier now rejects reordered or
  non-canonical JSON members, invalid UTF-8, null optional members, a missing
  `iat`, a present root `par_hash`, non-canonical base64url, presentations
  over 64 KiB, lists over 256 entries and IDs over 255 bytes.
- **Safer errors and zero values.** Backend errors are returned as
  `ErrBackend` without driver detail; constructors return `ErrInvalidConfig`;
  zero `Minter`, `Deriver`, `Verifier` and `Memory` values fail closed rather
  than panicking.
- Added `ErrBackend`, `ErrInvalidConfig`, `ErrNoRevocationBackend`,
  `PublicKeyThumbprint`, and the exported bounds `MaxPresentationBytes`,
  `MaxListEntries` and `MaxIDLength`.
- `mise run api-diff` against `v0.2.0` reports the expected pre-1.0
  incompatible changes from the public-package move; see `UPGRADING.md`.

### Documentation

- Added a complete quickstart, best-practices and use-cases guide, plus
  runnable `examples/quickstart`, `examples/holder-key` and
  `examples/revocation` programs and a godoc `Example`.
- Documented the verifier-first rollout rule for vocabulary and format
  changes, the required revocation decision, verifier-owned time, key
  rotation, and the separate reservation-service module.
- Recorded the two-person, signed-tag, security-response and pre-v1 audit
  policy in `SECURITY.md`.

## v0.2.0 — 2026-10-27

- Additive conformance-suite coverage after CAS became the first external
  consumer: all five non-identity permutations of a three-link chain, dropped,
  repeated and spliced links, malformed presentations, truncations, altered
  bytes, and every caveat kind.
- Fixed the standard-claim partition: `expires_at`, `not_before`,
  `permission_set` and `resource_scope` are now refused in `cav` at mint and
  decode, matching `docs/wire-format.md`.
- Documented that atomicity of a redemption belongs to the consumer's
  transaction; two concurrent `MaxUses(1)` redemptions can both pass
  verification against any `Counters` adapter.

## v0.1.1 — 2026-10-24

- Fixed the redaction test's length needle so it depends on the secret, not on
  a timestamp that happened to contain the same number.
- Added `RendersOnlyARedactionMarker` as the positive half of the redaction
  assertion.

## v0.1.0 — 2026-10-23

- First release: attenuable capability tokens as a chain of plain JWTs,
  typed caveats, offline verification, chain revocation, and the published
  wire format with committed vectors.
