# C019 — Duplicate Inside metadata

`metadata` carries `note` twice. metadata is part of the certificate the
emission binding hashes, so a duplicate there is as ambiguous as anywhere
else (CCSP/1 §8.1).
Expected: REJECTED (INPUT_COMBINATION_VALID)