# F014 — Single-Key Quorum

The bootstrap entry declares quorum k = 1. The single-key root is not
representable under /1: 2 <= k <= n (system-manifest/1 §6, §7.3).
Expected: REJECTED (FOUNDATION_FINGERPRINT_RECOMPUTED)