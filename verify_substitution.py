#!/usr/bin/env python3
"""
verify_substitution.py -- no Swift/macOS toolchain needed.

Starts mock_registry.py in-process and makes real HTTP requests against it
(the same requests RegistryClient.resolve()/fetch() would make), proving:

  1. HEAD /v2/{name}/manifests/{pinned-digest} reports a
     Docker-Content-Digest consistent with what was requested (looks
     legitimate).
  2. GET  /v2/{name}/manifests/{pinned-digest} returns a body whose actual
     SHA256 does NOT match that digest.
  3. The substituted manifest's OWN referenced blobs (config + layer) DO
     correctly hash to their own claimed digests -- proving the gap is
     specifically at the manifest layer, not a general "server can lie"
     triviality.

This is a sanity check you can run in seconds without any toolchain. It is
NOT a replacement for the Swift harness (Sources/manifest-poc/main.swift) --
that one calls the actual project code and is the real reproduction. This
script only proves the HTTP-level substitution mechanism the Swift harness
relies on is real and self-consistent.
"""
import hashlib
import http.server
import json
import threading
import time
import urllib.request

import mock_registry as reg


def main():
    server = http.server.HTTPServer(("127.0.0.1", 0), reg.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)

    print(f"[*] Mock malicious registry listening on 127.0.0.1:{port}")
    print(f"[*] Pinned/expected digest: {reg.EXPECTED_DIGEST}")
    print()

    url = f"http://127.0.0.1:{port}/v2/victim/image/manifests/{reg.EXPECTED_DIGEST}"

    print("[*] HEAD request (what RegistryClient.resolve() sends):")
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req) as resp:
        digest_hdr = resp.headers.get("Docker-Content-Digest")
        print(f"    status: {resp.status}")
        print(f"    Docker-Content-Digest: {digest_hdr}")
        print(f"    matches requested digest: {digest_hdr == reg.EXPECTED_DIGEST}")

    print()
    print("[*] GET request (what RegistryClient.fetch() sends):")
    with urllib.request.urlopen(url) as resp:
        body = resp.read()
    actual_digest = "sha256:" + hashlib.sha256(body).hexdigest()
    print(f"    status: {resp.status}, body length: {len(body)}")
    print(f"    requested/pinned digest : {reg.EXPECTED_DIGEST}")
    print(f"    actual SHA256 of body   : {actual_digest}")
    mismatch = actual_digest != reg.EXPECTED_DIGEST
    print(f"    MISMATCH: {mismatch}")

    print()
    if mismatch:
        print("[+] CONFIRMED: server returned content that does not hash to the")
        print("    digest it was requested by, while claiming (via the HEAD")
        print("    response) that it does. This is the exact substitution")
        print("    OE1107240405872 describes.")
    else:
        print("[!] Unexpected: no mismatch. mock_registry.py may be misconfigured.")

    print()
    print("[*] Verifying the substituted manifest's OWN blobs self-verify")
    print("    (proving the gap is manifest-specific, not a broken mock):")
    manifest = json.loads(body)
    for kind, desc in [("config", manifest["config"])] + [("layer", l) for l in manifest["layers"]]:
        burl = f"http://127.0.0.1:{port}/v2/victim/image/blobs/{desc['digest']}"
        with urllib.request.urlopen(burl) as bresp:
            bbody = bresp.read()
        bactual = "sha256:" + hashlib.sha256(bbody).hexdigest()
        ok = bactual == desc["digest"]
        print(f"    {kind}: claimed={desc['digest']}")
        print(f"      {'':<8}actual ={bactual}  match={ok}")

    server.shutdown()


if __name__ == "__main__":
    main()
