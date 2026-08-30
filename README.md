# PoC for OE1107240405872 — manifest/index content not verified against digest

Apple's reviewer closed the original report with a specific, fair
objection: *"The included script does not call the affected code; it
represents the absence of a check rather than testing the real code path.
We are therefore not able to confirm from the material provided whether a
substituted manifest would in fact be accepted."*

This package answers that directly: it calls the **real** project code
(`RegistryClient.fetch`, `RegistryClient.fetchData`, `ImageStore.pull`)
against a minimal malicious/compromised registry, and runs it on real macOS
via CI — the same approach that got OE1107563755116 (the ext4 report)
re-evaluated.

## What's in this package

- **`mock_registry.py`** — a minimal malicious OCI registry. It computes the
  SHA256 of a legitimate-looking manifest (`EXPECTED_MANIFEST_BYTES` — this
  is the digest a caller would pin) and, for every request addressed to
  that exact digest — both the `HEAD` `resolve()` uses and the `GET`
  `fetch()` uses — returns a **different** manifest body
  (`SUBSTITUTED_MANIFEST_BYTES`) referencing attacker-chosen config/layer
  blobs instead. Those attacker blobs are served correctly and self-
  consistently at `/v2/{name}/blobs/{digest}` (blob-level verification is
  real and enforced by the project; the gap is specifically at the manifest
  layer, and the PoC only claims what's actually true there).
- **`verify_substitution.py`** — no Swift/macOS needed. Starts the mock
  registry in-process and makes the same HTTP requests
  `RegistryClient.resolve()`/`fetch()` would, proving the HTTP-level
  substitution mechanism is real before you even get to Swift.
- **`Sources/manifest-poc/main.swift`** — the real reproduction. Two parts:
  1. Calls `RegistryClient.fetch(name:descriptor:)` directly with a
     `Descriptor` pinned to the *expected* digest, against the mock
     registry. Shows it returns successfully with the *substituted*
     manifest, no error. Then independently fetches the same URL as raw
     bytes and hashes it, to show explicitly that the body doesn't match
     what was requested — using the project's own `SHA256.Digest
     .digestString` helper (`ContainerizationOCI/Content/SHA256+Extensions.swift`),
     the exact comparison `ImageStore+Import.swift` uses for blobs.
  2. Calls `ImageStore(path:).pull(reference:insecure:)` — the exact public
     API `container pull` uses — with a digest-pinned reference pointed at
     the mock registry. Shows the full pull succeeds and imports the
     attacker's substituted layers, matching the original report's literal
     reproduction steps (`container pull <registry>/<name>@sha256:<digest>`).
- **`.github/workflows/poc.yml`** — runs the above on GitHub's hosted macOS
  runner (real Apple-provided VM), starting the mock registry as a
  background process, then running the harness against it, capturing full
  output.

## How to run it

### Option A — GitHub Actions (recommended, real macOS)

1. Push this whole folder's contents to a GitHub repo (root-level —
   `Package.swift`, `mock_registry.py`, `.github/`, `Sources/`, etc. all at
   the top, not nested in a subfolder).
2. Actions tab → `manifest-poc` → Run workflow.
3. Check the run's Summary for full output, or download the
   `manifest-poc-macos-log` artifact.

### Option B — no Swift needed, sanity-check the mechanism first

```bash
python3 verify_substitution.py
```

Confirms the HTTP-level substitution (HEAD reports the pinned digest, GET
returns non-matching content, the substituted manifest's own blobs
self-verify) in a few seconds, no toolchain required.

### Option C — run the Swift harness yourself on a Mac

```bash
python3 mock_registry.py 0    # note the printed MOCK_REGISTRY_PORT and EXPECTED_DIGEST
swift build
.build/debug/manifest-poc <port> <expectedDigest>
```

## Expected output (what "the bug reproduced" looks like)

Part 1 should print something like:

```
[+] client.fetch() returned SUCCESSFULLY -- no digest-mismatch error was thrown.
    Returned manifest has 1 layer(s).
    layers[0].digest = sha256:<attacker layer digest>
    config.digest    = sha256:<attacker config digest>
...
[+] CONFIRMED: the response body does NOT hash to the digest it was
    requested/pinned by. client.fetch() above accepted and decoded it anyway.
```

Part 2 should print:

```
[+] pull() SUCCEEDED. No digest-mismatch error at any point.
...
[+] IMPACT CONFIRMED: a pull pinned to a specific digest silently accepted
    and imported a completely different, attacker-chosen manifest and its
    referenced layers, exactly as OE1107240405872 describes.
```

If instead you see a thrown digest-mismatch error at either point, the gap
has likely been fixed since this was written — that would itself be useful
information to report back.

## Source confirmation (pulled fresh from `apple/containerization` `main`
before building this)

`RegistryClient+Fetch.swift` — `fetch<T: Codable>` has no verification at
all:

```swift
public func fetch<T: Codable>(name: String, descriptor: Descriptor) async throws -> T {
    ...
    components.path = "/v2/\(name)/\(resource)/\(descriptor.digest)"
    ...
    return try await requestJSON(components: components, headers: headers)
}
```

`resolve(name:tag:)` — accepts whatever `Docker-Content-Digest` the server
sends, never compared against what was requested:

```swift
public func resolve(name: String, tag: String) async throws -> Descriptor {
    ...
    let digest = try ParsedDigest(parsing: header).description
    ...
    return Descriptor(mediaType: type, digest: digest, size: size)
}
```

`ImageStore+Import.swift` — confirms the asymmetry exactly. Blob content is
verified:

```swift
private func fetchBlob(_ descriptor: Descriptor) async throws {
    ...
    let (_, digest) = try await client.fetchBlob(name: name, descriptor: descriptor, into: tempFile, progress: progress)
    guard digest.digestString == descriptor.digest else {
        throw ContainerizationError(.internalError, message: "digest mismatch")
    }
    ...
}
```

Manifest/index content is not — `getManifestContent` falls straight
through to the unverified `client.fetch`:

```swift
private func getManifestContent<T: Sendable & Codable>(descriptor: Descriptor) async throws -> T {
    ...
    return try await self.client.fetch(name: name, descriptor: descriptor)
}
```

`ImageStore.swift`'s `pull(reference:...)` confirms the report's
"compounding" claim — `ref.digest` (the pinned digest from
`name@sha256:...`) is passed straight into `resolve(name:tag:)` as `tag`,
and `resolve()`'s own result is never cross-checked against it:

```swift
guard let tag = ref.tag ?? ref.digest else { ... }
let rootDescriptor = try await client.resolve(name: name, tag: tag)
```

All of this matches the original report's claims exactly; nothing here
required any correction to the underlying analysis, only a real
executing demonstration of it.
