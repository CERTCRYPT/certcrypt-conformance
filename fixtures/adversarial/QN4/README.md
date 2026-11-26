# QN4 — Equivocation: Two Successor Sets Over One Predecessor State

The bootstrap quorum authorizes TWO distinct successor-bindings sharing the
same (system_id, predecessor_manifest_fingerprint, predecessor_manifest_
sequence, predecessor_kid) but differing in successor_kid/members/valid_from.
Each observation carries a verifying predecessor quorum (m0, m1), so both
are authenticated. Under system-manifest/1 §12.5 this is equivocation: the
implicated manifest versions are terminally invalid.
Expected: REJECTED (FOUNDATION_EQUIVOCATION_DETECTED)