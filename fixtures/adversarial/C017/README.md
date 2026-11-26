# C017 — Rules Version Not Evaluated By The Verifier

A correctly signed certificate names `payload.rules_version` "rules/9999-01",
which the verifier does not evaluate. It cannot decide the certificate
under rules it does not hold (CCSP/1 §7.3).
Expected: UNSUPPORTED (BASE_CERTIFICATE_STRUCTURE_VALID)