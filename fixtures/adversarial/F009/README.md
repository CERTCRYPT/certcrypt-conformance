# F009 — Bootstrap Statement Id Not the Registered One

A correctly quorum-signed statement over the published bootstrap manifest
(same root fingerprint) carries a foundation_statement_id other than the one
the registry entry declares. Matching the root is not enough: the registered
bootstrap is one exact statement.
Expected: REJECTED (FOUNDATION_BOOTSTRAP_MATCHES_RULES)