# C012 — Unknown Member In The Signer

The signer object carries a `pub_b64` member beside its two component
keys. The signer is closed (CCSP/1 §7.4).
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)