# Q005 — Composite Domain-Separation Mismatch

The component signatures were made over M' with the canonical label, but the
certificate declares a different domain. Re-deriving M' with the wrong label
makes both components fail — this is the anti-stripping binding.
Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)