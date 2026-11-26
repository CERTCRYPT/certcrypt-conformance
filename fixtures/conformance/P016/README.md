# P016 — Email Original Material Matches

Target `issued`: the certificate commits to one complete emitted message under
`subject.email/1`. The delivered message differs only in line-ending style, a
header-fold position at existing whitespace, and trailing body terminators.
Those representations have the same canonical bytes (subject.email/1 §11).
Expected: ISSUED_VALID