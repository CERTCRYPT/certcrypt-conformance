# V032 — Multi-Auth Bridges Disagree on batch_binding_preimage

The batch binding is batch-level (one memo per settlement); two bridges
carrying different batch_binding_preimage is incoherent.
Expected: INDEPENDENT_INVALID (CAPACITY_NOT_RECONSTRUCTED)