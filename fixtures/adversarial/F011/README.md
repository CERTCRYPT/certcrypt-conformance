# F011 — Member Key in Compressed SEC1 Form

A bootstrap member's P-256 key is the same point compressed to 33 bytes. The
field admits one encoding, SEC1 uncompressed (65 bytes): another encoding of
the same key would give the manifest another fingerprint (system-manifest/1
§7.3, composite-signature/1 §9.1).
Expected: REJECTED (FOUNDATION_FINGERPRINT_RECOMPUTED)