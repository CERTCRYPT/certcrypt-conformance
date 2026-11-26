# V082 — Transit-Mutated Email Does Not Match

Target `issued`: the certificate commits to the emitted message, while the
delivered copy contains an additional transit header. The profile preserves
header presence, so this is different material, not an equivalent export.
Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)