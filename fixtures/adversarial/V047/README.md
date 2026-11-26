# V047 — Manifest Batch Id Diverges From the Anchored Batch Id

The memo anchors batch_binding_preimage.batch_id = batch-P001, and the
signed settlement_ref names it, but batch_manifest.batch_id declares
batch-P001-restated. The material's copy of the batch identity MUST equal
the anchored value (settlement.aggregated.xrpl/1 §10.1; settlement.binding/1 §6).
Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)