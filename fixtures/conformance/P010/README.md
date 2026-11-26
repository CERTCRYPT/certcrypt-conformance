# P010 — Proof With a Node Attestation

The Proof of Independence carries `node_attestation` (independence.proof/1
§10.15): the recognized node that carried the submission and the instant its
recognition was checked. The attestation sits inside the signed view, so the
proof signature authenticates it; no registry is consulted. The verifier
returns INDEPENDENT_VALID and reports the attested node in `attested_node`.