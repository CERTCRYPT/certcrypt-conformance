# V076 — Authorization For Another Role

The Level-1 binding, signed by the system domain, and the projected authorization
agree on `authorized_role: "capacity_observer"`. Every signature verifies and the
evidence digest is the committed one; the authorization does not grant the
commitment-holder role (capacity.holder-authorization/1 §7 step 2,
capacity.evidence/1 §8 step 3).
Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)