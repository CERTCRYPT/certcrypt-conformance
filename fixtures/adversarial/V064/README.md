# V064 — Commitment Issued Before The Authorization Window

The capacity commitment's issued_at (2026-04-11T12:00:00Z) is one second
before the Level-1 binding's valid_from. The window is inclusive at both
ends, and this instant is outside it (capacity.evidence/1 §7).
Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)