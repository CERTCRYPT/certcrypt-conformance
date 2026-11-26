# V044 — Manifest Total Diverges From the Anchored Total

The payment burns 10.00 and the memo anchors 10.00, but
batch_manifest.total_quantity declares 11.00. The material's copy of the
total MUST equal the anchored batch_binding_preimage.total_quantity.
Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)