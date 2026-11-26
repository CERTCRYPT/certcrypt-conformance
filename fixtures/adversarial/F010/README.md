# F010 — Manifest Member Outside the Closed Schema

The embedded manifest carries a top-level member system-manifest/1 §6 does
not define. The fingerprint is recomputed over it and the statement re-signed,
so only the closed schema rejects it.
Expected: REJECTED (FOUNDATION_FINGERPRINT_RECOMPUTED)