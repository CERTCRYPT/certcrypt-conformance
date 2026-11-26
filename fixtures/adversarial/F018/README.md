# F018 — Level-1 ML-DSA Key of the Wrong Length

The statement's Level-1 ML-DSA-65 key is one byte short of the 1952 bytes
FIPS 204 fixes, and the quorum re-signs the statement over it
(system-foundation/1 §6).
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)