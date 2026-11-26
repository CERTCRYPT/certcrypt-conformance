# F007 — Foundation Valid Internally But Mismatches Published Bootstrap

A separate k-of-n composite quorum produces a valid, correctly
quorum-signed foundation statement embedding its own bootstrap manifest,
but its derived system_root_fingerprint does not match the published
bootstrap for rules/conformance.
This is the exact attack system-domain/1 and system-foundation/1 prevent:
a valid-looking foundation cannot redefine the CERTCRYPT root.
Expected: REJECTED (FOUNDATION_BOOTSTRAP_MATCHES_RULES)