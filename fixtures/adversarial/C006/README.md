# C006 — Wrapper Member At The Top Level

The certificate object carries a `receipt` member. The top level is closed
(CCSP/1 §6): wrappers and receipts live outside the certificate.
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)