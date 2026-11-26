# F012 — Level-1 Key in Compressed SEC1 Form

The statement's Level-1 capacity key is the same point compressed to 33 bytes,
and the quorum re-signs the statement over it. The field admits only the
65-byte SEC1 uncompressed encoding (system-foundation/1 §6).
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)