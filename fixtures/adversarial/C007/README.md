# C007 — Unknown Member Inside The Anchor

A correctly signed certificate adds `issuer_id` to `payload.anchor`, which
is closed (CCSP/1 §7.3.1).
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)