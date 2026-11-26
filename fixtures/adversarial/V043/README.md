# V043 — Burn Below the Anchored Total, Manifest Restated to Match

The memo anchors batch_binding_preimage.total_quantity = 10.00. The payment
burns 5.00, and capacity_consumption_proof.total_quantity and
batch_manifest.total_quantity are both restated as 5.00, so every
unanchored copy of the total agrees with the burn. The verifier compares the
burned quantity with the anchored preimage total, not with the manifest
(settlement.aggregated.xrpl/1 §10.1).
Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)