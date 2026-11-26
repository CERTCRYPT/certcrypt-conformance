# V060 — Settlement Quantity `1.000 CERT`

settlement_action.quantity is `1.000 CERT`: three fractional digits, one more than the asset scale. The quantity is
`<integer>.<2 digits> CERT` and strictly positive
(settlement.aggregated.xrpl/1 §9.3).
Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)