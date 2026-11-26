# C018 — Escaped Duplicate Inside The Anchor

`payload.anchor` carries `issued_at` twice; the second spelling escapes a
letter (`\u0069ssued_at`). Member names are compared after decoding, so this
is a duplicate, and any duplicate is non-conformant at any depth (CCSP/1 §8.1).
Expected: REJECTED (INPUT_COMBINATION_VALID)