# Upgrading

`captoken` is pre-1.0: a minor release may break the API. This file records the
steps for each breaking or migration-relevant change. Incompatible API changes
are reported by `mise run api-diff` and must also be listed here and in
`CHANGELOG.md`.

## From v0.2.0 to the unreleased change set

### 1. Replace the AST API golden-file gate

The root `api.txt`, `api_test.go`/`TestAPIGolden`, and `mise run api` are
removed. Do not recreate them. The gate now uses the Go project's compatibility
tooling:

```bash
mise run api-diff       # apidiff against the last root tag; dirty tree is fine
mise run release-check  # gorelease from a clean checkout before tagging
```

`api-diff` ignores `internal/...`, because internal packages are not part of
the public contract even when the facade aliases them. Before 1.0 an
incompatible change is reported and exits 0; record it here and in
`CHANGELOG.md`. From 1.0 set `API_DIFF_STRICT=1` so a break fails the gate, and
publish a new major module path for the break.

The package move and API changes below are incompatible, so `mise run api-diff`
against `v0.2.0` reports them. They are allowed before 1.0 and are listed here.

### 2. Revocation is now required

`NewVerifier` refuses a verifier with neither `Revocations` nor an explicit
opt-out:

```go
// Production: supply the backend.
Revocations: myRevocations,

// Deliberate no-revocation deployment:
NoRevocation: true,

// Both at once is a configuration error.
```

Add `NoRevocation: true` only if the deployment genuinely has no revocation
requirement. `captokentest.Wiring.Revocations` is required for the same reason.

### 3. Time is verifier-owned

`Verify` ignores `Request.Now`; it always uses `VerifierConfig.Clock`. For a
test or replay that needs a specific instant, call `VerifyAt`:

```go
verified, err := verifier.VerifyAt(ctx, token, req, instant)
```

`CheckAll` now refuses a zero `Request.Now`; direct callers must set it.

### 4. Rename `Verified.Resources`

Change field reads from `verified.Resources` to
`verified.TerminalResources`. The field is the terminal link's scope; it is not
the intersection of every link.

### 5. Update key handling

- `MinterConfig.RootKey` and the holder key passed to `Derive` are now
  `crypto.Signer`, so `ed25519.PrivateKey` values still compile and HSMs can
  be used directly.
- To keep the holder's private key out of the issuer, set
  `MintSpec.HolderPublicKey`; `Minted.HolderKey` is then nil.
- Identity and small-order Ed25519 public keys are rejected by constructors
  and JWK decoding.

### 6. Expect stricter decoding

Tokens that were previously accepted but are not canonical are now refused:
reordered members, invalid UTF-8, `null` optional members, missing `iat`, a
present root `par_hash`, non-canonical base64url, presentations over 64 KiB,
lists over 256 entries and IDs over 255 bytes. Re-issue such tokens rather than
relaxing the verifier.

### 7. Use mise for the toolchain

The module now targets Go 1.27.3. Run:

```bash
mise install
mise run check
```

CI does the same and checks out full tags (`fetch-depth: 0`) so `api-diff` can
find the previous release. Do not pin Go, gofumpt or golangci-lint a second
time in workflow files.

### 8. Generate-check for this library

This repository has no `sqlc.yaml`/`sqlc.yml`/`sqlc.json`, `buf.gen.yaml` or
generated code, so there is no `generate` task. `mise run generate-check` verifies that no generator
configuration or `go:generate` directive has appeared; if one is added, wire a
real generation/diff task instead of leaving the check passing.

### 9. Release validation

The release workflow runs the normal gate and then:

```bash
go run golang.org/x/exp/cmd/gorelease@v0.0.0-20261014143641-f0251eb4aa3e \
  -base=latest -version=vX.Y.Z
```

The nested module under `docs/superpowers/spikes` is a throwaway spike. It is
not published, not tagged, and not passed to gorelease.
