# V057 — AI-Decision Output Does Not Match the Committed Record

The subject.ai-decision/1 record matches the certificate's commitment, and the
delivered prompt matches the part named `prompt`; the part delivered as `answer` is
different, so it does not reproduce that part's salted commitment
(verifier-toolkit/1 §8.5.6). Like any material mismatch, a failure of the Issued
route.
Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)