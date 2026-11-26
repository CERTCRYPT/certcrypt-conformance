# V046 — Manifest Leaf Count Diverges From the Anchored Leaf Count

The memo anchors batch_binding_preimage.leaf_count = 2, but
batch_manifest.leaf_count declares 3. The material's
copy of the batch size MUST equal the anchored value
(settlement.aggregated.xrpl/1 §10.1; settlement.binding/1 §6).
Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)