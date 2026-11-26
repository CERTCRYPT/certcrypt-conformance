# V015 — Parser Tolerance Rescue

The base certificate repeats its top-level `schema` member. A parser that
keeps the last (or the first) value would read a valid certificate; CCSP/1
§8.1 makes any duplicate member non-conformant.
Expected: REJECTED (INPUT_COMBINATION_VALID)