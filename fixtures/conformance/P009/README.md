# P009 — Successor Binding Authorized by the Predecessor Quorum

The foundation is accompanied by one successor-binding observation: a
system-manifest/1 §9 payload naming the bootstrap entry as predecessor and a
2-of-2 successor quorum, signed by bootstrap members m0 and m1 (k=2 of n=3).
Both composite signatures verify over SHA3-256(UTF-8(JCS(payload))), so the
rotation is authorized (§12.3) and the observation is accepted.
Expected: INDEPENDENT_VALID