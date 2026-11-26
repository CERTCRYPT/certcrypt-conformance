# C002 — Reserved payload.consensus

A correctly signed certificate carries `payload.consensus`, a name CCSP/1 §9
reserves. Anchoring and settlement live outside the certificate.
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)