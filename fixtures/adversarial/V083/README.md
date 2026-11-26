# V083 — Missing Base Certificate

The artifact set carries an independence proof and settlement material but no base certificate. `auto` therefore resolves to Independent, and the absent certificate makes the request incomplete rather than malformed.
Expected: INCOMPLETE (BASE_CERTIFICATE_PRESENT)